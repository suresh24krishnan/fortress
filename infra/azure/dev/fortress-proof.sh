az login --identity
az keyvault secret show --vault-name kv-fortress-dev --name fortress-test-secret --query "{name:name,id:id,created:attributes.created,updated:attributes.updated}" -o json
