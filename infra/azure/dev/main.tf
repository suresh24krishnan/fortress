terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "fortress" {
  name     = var.resource_group_name
  location = var.location
}

resource "azurerm_virtual_network" "fortress_vnet" {
  name                = "${var.name_prefix}-vnet"
  location            = azurerm_resource_group.fortress.location
  resource_group_name = azurerm_resource_group.fortress.name
  address_space       = [var.vnet_cidr]
}

# Zone 1 – Air-Lock
resource "azurerm_subnet" "zone1_airlock" {
  name                 = "${var.name_prefix}-zone1-airlock"
  resource_group_name  = azurerm_resource_group.fortress.name
  virtual_network_name = azurerm_virtual_network.fortress_vnet.name
  address_prefixes     = [var.zone1_cidr]
}

# Zone 2 – Control Plane
resource "azurerm_subnet" "zone2_control" {
  name                 = "${var.name_prefix}-zone2-control"
  resource_group_name  = azurerm_resource_group.fortress.name
  virtual_network_name = azurerm_virtual_network.fortress_vnet.name
  address_prefixes     = [var.zone2_cidr]
}

# Zone 3 – Sanctum
resource "azurerm_subnet" "zone3_sanctum" {
  name                 = "${var.name_prefix}-zone3-sanctum"
  resource_group_name  = azurerm_resource_group.fortress.name
  virtual_network_name = azurerm_virtual_network.fortress_vnet.name
  address_prefixes     = [var.zone3_cidr]
}

# Zone 4 – Vault
resource "azurerm_subnet" "zone4_vault" {
  name                 = "${var.name_prefix}-zone4-vault"
  resource_group_name  = azurerm_resource_group.fortress.name
  virtual_network_name = azurerm_virtual_network.fortress_vnet.name
  address_prefixes     = [var.zone4_cidr]
}

# Zone 5 – Audit
resource "azurerm_subnet" "zone5_audit" {
  name                 = "${var.name_prefix}-zone5-audit"
  resource_group_name  = azurerm_resource_group.fortress.name
  virtual_network_name = azurerm_virtual_network.fortress_vnet.name
  address_prefixes     = [var.zone5_cidr]
}

# -----------------------------
# Zero-Egress Sanctum (Zone 3)
# -----------------------------

resource "azurerm_network_security_group" "zone3_sanctum_nsg" {
  name                = "${var.name_prefix}-nsg-zone3-sanctum-zero-egress"
  location            = azurerm_resource_group.fortress.location
  resource_group_name = azurerm_resource_group.fortress.name
}

# Allow intra-VNet traffic (needed so Zone3 can talk to Zone2, Vault, Audit privately)
resource "azurerm_network_security_rule" "zone3_allow_vnet_out" {
  name                        = "AllowVNetOutbound"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "VirtualNetwork"
  destination_address_prefix  = "VirtualNetwork"
  resource_group_name         = azurerm_resource_group.fortress.name
  network_security_group_name = azurerm_network_security_group.zone3_sanctum_nsg.name
}

# Allow DNS to Azure-provided DNS (required for private DNS resolution later)
resource "azurerm_network_security_rule" "zone3_allow_dns_out" {
  name                        = "AllowDNSOutbound"
  priority                    = 110
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_range      = "53"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.fortress.name
  network_security_group_name = azurerm_network_security_group.zone3_sanctum_nsg.name
}

# Hard deny: everything else outbound
resource "azurerm_network_security_rule" "zone3_deny_all_out" {
  name                        = "DenyAllOutbound"
  priority                    = 4096
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.fortress.name
  network_security_group_name = azurerm_network_security_group.zone3_sanctum_nsg.name
}

resource "azurerm_subnet_network_security_group_association" "zone3_sanctum_assoc" {
  subnet_id                 = azurerm_subnet.zone3_sanctum.id
  network_security_group_id = azurerm_network_security_group.zone3_sanctum_nsg.id
}

# Route table: explicit association for auditability (no custom routes yet)
resource "azurerm_route_table" "zone3_sanctum_rt" {
  name                = "${var.name_prefix}-rt-zone3-sanctum"
  location            = azurerm_resource_group.fortress.location
  resource_group_name = azurerm_resource_group.fortress.name
}

resource "azurerm_subnet_route_table_association" "zone3_sanctum_rt_assoc" {
  subnet_id      = azurerm_subnet.zone3_sanctum.id
  route_table_id = azurerm_route_table.zone3_sanctum_rt.id
}

# -----------------------------
# Phase 2.1: Vault + PrivateLink
# -----------------------------

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "fortress_kv" {
  name                       = var.key_vault_name
  location                   = azurerm_resource_group.fortress.location
  resource_group_name        = azurerm_resource_group.fortress.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"

  # Critical: no public access
  public_network_access_enabled = false

  # We'll use RBAC (cleaner + enterprise-aligned)
  enable_rbac_authorization = true

  soft_delete_retention_days = 7
  purge_protection_enabled   = false
}

# Private DNS zone for Key Vault Private Link
resource "azurerm_private_dns_zone" "kv_plink_dns" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.fortress.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "kv_dns_link" {
  name                  = "${var.name_prefix}-kv-dns-link"
  resource_group_name   = azurerm_resource_group.fortress.name
  private_dns_zone_name = azurerm_private_dns_zone.kv_plink_dns.name
  virtual_network_id    = azurerm_virtual_network.fortress_vnet.id
}

# Private Endpoint lives in Zone 4 (Vault subnet)
resource "azurerm_private_endpoint" "kv_private_endpoint" {
  name                = "${var.name_prefix}-pe-kv"
  location            = azurerm_resource_group.fortress.location
  resource_group_name = azurerm_resource_group.fortress.name
  subnet_id           = azurerm_subnet.zone4_vault.id

  private_service_connection {
    name                           = "${var.name_prefix}-psc-kv"
    private_connection_resource_id = azurerm_key_vault.fortress_kv.id
    is_manual_connection           = false
    subresource_names              = ["vault"]
  }

  private_dns_zone_group {
    name                 = "kv-dns-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.kv_plink_dns.id]
  }
}
