output "vnet_name" {
  value = azurerm_virtual_network.fortress_vnet.name
}

output "subnets" {
  value = {
    zone1 = azurerm_subnet.zone1_airlock.name
    zone2 = azurerm_subnet.zone2_control.name
    zone3 = azurerm_subnet.zone3_sanctum.name
    zone4 = azurerm_subnet.zone4_vault.name
    zone5 = azurerm_subnet.zone5_audit.name
  }
}

output "key_vault_name" {
  value = azurerm_key_vault.fortress_kv.name
}

output "key_vault_private_endpoint" {
  value = azurerm_private_endpoint.kv_private_endpoint.name
}
