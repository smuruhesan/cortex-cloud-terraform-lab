# This Terraform configuration provisions an Azure Virtual Machine with intentional security flaws
# for demonstration purposes in a Cortex Cloud security scanning lab.

# Configure the Azure provider
# We are intentionally not specifying a version constraint for the provider,
# which can lead to unexpected behavior with future provider updates.
terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
  }
}

provider "azurerm" {
  features {}
  # No explicit version constraint, relying on latest available.
  # This can be a security risk if new versions introduce breaking changes or vulnerabilities.
}

# 1. Insecure Network Security Group (NSG) - Exposing SSH/RDP to the Internet
# This NSG allows inbound SSH (port 22) and RDP (port 3389) from *any* IP address (0.0.0.0/0).
# This is a critical security flaw, making the VM vulnerable to brute-force attacks.
resource "azurerm_resource_group" "vulnerable_rg" {
  name     = "vulnerable-terraform-rg"
  location = "East US"
}

resource "azurerm_network_security_group" "vulnerable_nsg" {
  name                = "vulnerable-nsg"
  location            = azurerm_resource_group.vulnerable_rg.location
  resource_group_name = azurerm_resource_group.vulnerable_rg.name

  security_rule {
    name                       = "AllowSSHFromAny"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "0.0.0.0/0" # Critical: Allows SSH from anywhere
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowRDPFromAny"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "0.0.0.0/0" # Critical: Allows RDP from anywhere
    destination_address_prefix = "*"
  }

  # No outbound rules are explicitly defined, relying on default, potentially overly permissive.
}

# 2. Virtual Network and Subnet
resource "azurerm_virtual_network" "vulnerable_vnet" {
  name                = "vulnerable-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.vulnerable_rg.location
  resource_group_name = azurerm_resource_group.vulnerable_rg.name
}

resource "azurerm_subnet" "vulnerable_subnet" {
  name                 = "vulnerable-subnet"
  resource_group_name  = azurerm_resource_group.vulnerable_rg.name
  virtual_network_name = azurerm_virtual_network.vulnerable_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# 3. Public IP Address - Directly attached to VM
# Attaching a public IP directly to a VM is generally discouraged for production environments
# unless absolutely necessary, as it exposes the VM directly to the internet.
resource "azurerm_public_ip" "vulnerable_public_ip" {
  name                = "vulnerable-public-ip"
  location            = azurerm_resource_group.vulnerable_rg.location
  resource_group_name = azurerm_resource_group.vulnerable_rg.name
  allocation_method   = "Dynamic" # Dynamic IP can change, but still exposes.
}

# 4. Network Interface with Insecure NSG Association
resource "azurerm_network_interface" "vulnerable_nic" {
  name                = "vulnerable-nic"
  location            = azurerm_resource_group.vulnerable_rg.location
  resource_group_name = azurerm_resource_group.vulnerable_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vulnerable_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vulnerable_public_ip.id
  }

  # Associate the insecure NSG with this NIC
  network_security_group_id = azurerm_network_security_group.vulnerable_nsg.id
}

# 5. Virtual Machine with Weak Authentication and Unencrypted OS Disk
resource "azurerm_linux_virtual_machine" "vulnerable_vm" {
  name                = "vulnerable-linux-vm"
  resource_group_name = azurerm_resource_group.vulnerable_rg.name
  location            = azurerm_resource_group.vulnerable_rg.location
  size                = "Standard_B1s" # Small size for lab purposes
  admin_username      = "adminuser"
  network_interface_ids = [
    azurerm_network_interface.vulnerable_nic.id,
  ]

  # Insecure: Using a hardcoded, simple password (or no SSH key)
  # For a lab, you might use a password, but in real-world, SSH keys are preferred.
  # If you want to make it even more vulnerable for scanning, remove the SSH key block entirely
  # and rely solely on password authentication, or use a very weak password.
  admin_password = "VeryWeakPassword123!" # Critical: Hardcoded, weak password

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    # No explicit encryption settings, relying on default (often not encrypted by default)
    # This is a potential data at rest vulnerability.
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  computer_name = "vulnerablevm"
  # No boot diagnostics configured, making troubleshooting harder and potentially hiding issues.
}

# 6. Storage Account with Public Access (Optional, but a common flaw)
# If you want to include a storage account vulnerability, uncomment the following block.
# This storage account is configured for public access, which is a major security risk.
/*
resource "azurerm_storage_account" "vulnerable_storage" {
  name                     = "vulnerablestorageacc001" # Must be globally unique
  resource_group_name      = azurerm_resource_group.vulnerable_rg.name
  location                 = azurerm_resource_group.vulnerable_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # Allow public access to blobs and containers
  allow_blob_public_access = true # Critical: Public access enabled
  min_tls_version          = "TLS1_0" # Critical: Uses an old, insecure TLS version
}
*/
