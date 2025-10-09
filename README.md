# WinRM Log Collector v2.2

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-Server%202008%20R2+-green.svg)](https://www.microsoft.com/en-us/windows-server)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-mrhenrike%2FWinRM--Log--Collector-brightgreen.svg)](https://github.com/mrhenrike/WinRM-Log-Collector)

## 🚀 Visão Geral

O **WinRM Log Collector v2.2** é uma solução PowerShell avançada para configuração e gerenciamento do Windows Remote Management (WinRM) para coleta de logs via Windows Event Collector (WEC) e Windows Event Forwarding (WEF). Esta versão oferece funcionalidades completas para configuração, monitoramento e troubleshooting de ambientes WinRM.

### ✨ Principais Recursos

- 🔧 **11 Actions Completas** - Configuração, monitoramento e troubleshooting
- 🛡️ **Suporte HTTP/HTTPS** - Listeners seguros com certificados
- 🔥 **Gerenciamento de Firewall** - Interface interativa para regras
- 📊 **Relatórios Detalhados** - Análise completa do sistema
- 🔐 **Verificação de Permissões** - Validação de usuários e grupos
- 📜 **Sistema de Logs Avançado** - Logging detalhado com rotação
- 🎯 **Interface Intuitiva** - Help integrado e exemplos práticos

---

## 📋 Índice

- [🚀 Início Rápido](#-início-rápido)
  - [⚡ Quick Reference](#-quick-reference)
- [📖 Guia Completo](#-guia-completo)
- [🎯 Actions Disponíveis](#-actions-disponíveis)
- [⚙️ Parâmetros de Configuração](#️-parâmetros-de-configuração)
- [🔧 Cenários Práticos](#-cenários-práticos)
- [🛡️ Segurança e Boas Práticas](#️-segurança-e-boas-práticas)
- [🔍 Troubleshooting](#-troubleshooting)
- [📚 Exemplos Avançados](#-exemplos-avançados)
- [📞 Suporte e Contribuição](#-suporte-e-contribuição)

---

## 🚀 Início Rápido

### 1. Download e Preparação

```powershell
# Clone o repositório
git clone https://github.com/mrhenrike/WinRM-Log-Collector.git
cd WinRM-Log-Collector

# Execute como Administrador
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 2. Configuração Básica HTTP

```powershell
# Configurar listener HTTP básico
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType http -User "domain\serviceaccount"
```

### 3. Verificar Status

```powershell
# Verificar configuração atual
.\winrmconfig_v2.2.ps1 -Action Status
```

### 4. Gerar Relatório

```powershell
# Gerar relatório completo
.\winrmconfig_v2.2.ps1 -Action Report
```

### ⚡ Quick Reference

| Ação | Comando | Descrição |
|------|---------|-----------|
| **Status** | `-Action Status` | Verificar status do sistema |
| **Enable HTTP** | `-Action Enable -ListenerType http -User "user"` | Configurar listener HTTP |
| **Enable HTTPS** | `-Action Enable -ListenerType https -User "user"` | Configurar listener HTTPS |
| **Disable** | `-Action Disable` | Remover listeners |
| **Firewall** | `-Action ConfigureFirewall` | Gerenciar regras de firewall |
| **Policies** | `-Action ConfigurePolicies` | Configurar políticas WinRM |
| **Permissions** | `-Action CheckPermissions -User "user"` | Verificar permissões |
| **Certificates** | `-Action ShowAllCerts` | Listar certificados |
| **Export CA** | `-Action ExportCACert -ExportCertPath "path"` | Exportar certificado CA |
| **Report** | `-Action Report` | Gerar relatório completo |
| **Help** | `-Action ShowHelp` | Ajuda rápida |
| **Help Long** | `-Action ShowHelpLong` | Ajuda detalhada |

---

## 📖 Guia Completo

### Pré-requisitos

#### ✅ Sistema Operacional
- **Windows Server 2008 R2** ou superior
- **Windows 10/11** (para desenvolvimento)
- **PowerShell 5.1** ou superior

#### ✅ Permissões
- **Privilégios administrativos** obrigatórios
- **Acesso ao registro** do sistema
- **Permissões de firewall** para configuração

#### ✅ Módulos PowerShell
```powershell
# Verificar módulos necessários
Get-Module -ListAvailable | Where-Object {$_.Name -match "NetSecurity|ActiveDirectory"}
```

### Formatos de Usuário Suportados

O script aceita múltiplos formatos de usuário:

| Formato | Exemplo | Descrição |
|---------|---------|-----------|
| `domain\user` | `CONTOSO\joao.silva` | Usuário de domínio |
| `user@domain.com` | `joao.silva@contoso.com` | Email format |
| `localuser` | `administrator` | Usuário local |
| `built-in` | `SYSTEM`, `NETWORK SERVICE` | Contas do sistema |

---

## 🎯 Actions Disponíveis

### 1. **Enable** - Configurar Listeners WinRM

Configura listeners HTTP/HTTPS para coleta de logs.

```powershell
# HTTP Listener (Recomendado para desenvolvimento)
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType http -User "domain\user"

# HTTPS Listener (Recomendado para produção)
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType https -User "domain\user" -ThumbPrint "ABC123..."

# Porta personalizada
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType http -Port 8080 -User "domain\user"
```

**Recursos:**
- ✅ Configuração automática do serviço WinRM
- ✅ Adição automática ao grupo "Event Log Readers"
- ✅ Configuração de políticas WinRM
- ✅ Detecção automática de certificados
- ✅ Suporte a portas personalizadas

### 2. **Disable** - Remover Listeners WinRM

Remove listeners configurados com interface interativa.

```powershell
# Remoção interativa (seleção manual)
.\winrmconfig_v2.2.ps1 -Action Disable

# Remoção de todos os listeners
.\winrmconfig_v2.2.ps1 -Action Disable -User "*"
```

**Recursos:**
- ✅ Interface interativa para seleção
- ✅ Remoção de regras de firewall associadas
- ✅ Desativação do serviço WinRM (se necessário)
- ✅ Limpeza completa da configuração

### 3. **Status** - Verificar Status do Sistema

Exibe status completo do WinRM e configurações relacionadas.

```powershell
# Status completo do sistema
.\winrmconfig_v2.2.ps1 -Action Status

# Status com porta específica
.\winrmconfig_v2.2.ps1 -Action Status -Port 5985
```

**Informações Exibidas:**
- 🔧 **Serviços**: WinRM, Firewall
- 📡 **Listeners**: HTTP/HTTPS ativos
- 🔥 **Firewall**: Regras WinRM/WEC
- 📋 **Políticas**: Configurações WinRM
- 🏢 **Domínio**: Status do controlador

### 4. **ConfigureFirewall** - Gerenciar Regras de Firewall

Interface interativa para gerenciamento de regras de firewall.

```powershell
# Gerenciamento interativo de firewall
.\winrmconfig_v2.2.ps1 -Action ConfigureFirewall
```

**Opções Disponíveis:**
1. **Deletar regras específicas**
2. **Deletar TODAS as regras WinRM**
3. **Adicionar nova regra WinRM**
4. **Desabilitar regras específicas**
5. **Desabilitar TODAS as regras WinRM**
6. **Sair**

### 5. **ConfigurePolicies** - Configurar Políticas WinRM

Configura políticas WinRM para otimizar a coleta de logs.

```powershell
# Configurar políticas WinRM
.\winrmconfig_v2.2.ps1 -Action ConfigurePolicies
```

**Políticas Configuradas:**
- ✅ **Allow Basic Authentication**: Habilitado
- ✅ **Allow Unencrypted Traffic**: Desabilitado
- ✅ **Allow Remote Server Management**: Configurado com filtros IP
- ✅ **Configure Log Access**: Configurado com SID específico

### 6. **CheckPermissions** - Verificar Permissões de Usuário

Analisa permissões detalhadas para coleta de logs.

```powershell
# Verificar permissões de usuário
.\winrmconfig_v2.2.ps1 -Action CheckPermissions -User "domain\user"
```

**Verificações Realizadas:**
- 👥 **Event Log Readers Group**: Membro do grupo
- 🔧 **WMI Permissions**: Acesso ao WMI
- 📡 **WinRM Access**: Configuração acessível
- 📜 **Event Log Access**: Leitura de logs
- 🔍 **Registry Permissions**: Acesso ao registro

### 7. **ShowAllCerts** - Listar Certificados Disponíveis

Exibe todos os certificados disponíveis para WinRM.

```powershell
# Listar todos os certificados
.\winrmconfig_v2.2.ps1 -Action ShowAllCerts
```

**Informações Exibidas:**
- 📜 **Certificados com Server Authentication EKU** (recomendados)
- 📜 **Outros certificados** (podem não ser adequados)
- 📊 **Resumo detalhado** com contadores
- 🔍 **Análise de adequação** para HTTPS

### 8. **ExportCACert** - Exportar Certificado CA

Exporta certificado CA para configuração de clientes.

```powershell
# Exportar certificado CA
.\winrmconfig_v2.2.ps1 -Action ExportCACert -ExportCertPath "C:\temp\ca-cert.cer"
```

**Recursos:**
- ✅ Seleção automática do certificado mais recente
- ✅ Exportação em formato .cer
- ✅ Validação de parâmetros obrigatórios
- ✅ Feedback detalhado do processo

### 9. **Report** - Gerar Relatório Abrangente

Gera relatório completo do sistema WinRM.

```powershell
# Gerar relatório completo
.\winrmconfig_v2.2.ps1 -Action Report
```

**Dados Coletados:**
- 💻 **Informações do Sistema**: OS, domínio, arquitetura
- 📡 **Status WinRM**: Serviço, listeners, configurações
- 📜 **Certificados**: Contagem e detalhes
- 🔥 **Firewall**: Regras WinRM/WEC
- 📋 **Políticas**: Configurações e status
- 💡 **Recomendações**: Sugestões automáticas

### 10. **ShowHelp** - Ajuda Simples

Exibe ajuda rápida e direta.

```powershell
# Ajuda simples
.\winrmconfig_v2.2.ps1 -Action ShowHelp
```

### 11. **ShowHelpLong** - Ajuda Detalhada

Exibe ajuda completa com exemplos e parâmetros.

```powershell
# Ajuda detalhada
.\winrmconfig_v2.2.ps1 -Action ShowHelpLong
```

---

## ⚙️ Parâmetros de Configuração

### Parâmetros Obrigatórios

| Parâmetro | Tipo | Descrição | Exemplo |
|-----------|------|-----------|---------|
| `-Action` | String | Ação a executar | `Enable`, `Status`, `Report` |

### Parâmetros por Action

#### **Enable/Disable**
| Parâmetro | Obrigatório | Descrição | Exemplo |
|-----------|-------------|-----------|---------|
| `-User` | ✅ | Usuário para coleta | `domain\user` |
| `-ListenerType` | ❌ | Tipo de listener | `http`, `https` |
| `-Port` | ❌ | Porta personalizada | `5985`, `8080` |
| `-ThumbPrint` | ❌ | Thumbprint do certificado | `ABC123...` |

#### **ExportCACert**
| Parâmetro | Obrigatório | Descrição | Exemplo |
|-----------|-------------|-----------|---------|
| `-ExportCertPath` | ✅ | Caminho para exportar | `C:\temp\ca.cer` |

#### **CheckPermissions**
| Parâmetro | Obrigatório | Descrição | Exemplo |
|-----------|-------------|-----------|---------|
| `-User` | ✅ | Usuário para verificar | `domain\user` |

### Parâmetros Opcionais

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `-AuthType` | String | `basic` | Tipo de autenticação |
| `-LogLevel` | String | `Error` | Nível de log |
| `-ConfigFile` | String | `config-sample.json` | Arquivo de configuração |
| `-LogPath` | String | `.\log` | Caminho dos logs |

### Validações de Parâmetros

```powershell
# AuthType válidos
- basic, negotiate, kerberos

# LogLevel válidos  
- Error, Warning, Info, Debug

# Porta válida
- 1-65535

# ListenerType válidos
- http, https
```

---

## 🔧 Cenários Práticos

### Cenário 1: Configuração Corporativa Completa

**Objetivo**: Configurar WinRM HTTPS para coleta de logs em ambiente corporativo.

```powershell
# 1. Verificar permissões do usuário
.\winrmconfig_v2.2.ps1 -Action CheckPermissions -User "wec-collector@contoso.com"

# 2. Listar certificados disponíveis
.\winrmconfig_v2.2.ps1 -Action ShowAllCerts

# 3. Configurar listener HTTPS
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType https -User "wec-collector@contoso.com" -ThumbPrint "ABC123..."

# 4. Configurar políticas WinRM
.\winrmconfig_v2.2.ps1 -Action ConfigurePolicies

# 5. Configurar firewall
.\winrmconfig_v2.2.ps1 -Action ConfigureFirewall

# 6. Exportar certificado CA
.\winrmconfig_v2.2.ps1 -Action ExportCACert -ExportCertPath "C:\WEC\Certificates\ca-cert.cer"

# 7. Verificar configuração
.\winrmconfig_v2.2.ps1 -Action Status

# 8. Gerar relatório final
.\winrmconfig_v2.2.ps1 -Action Report
```

### Cenário 2: Ambiente de Desenvolvimento/Teste

**Objetivo**: Configuração rápida HTTP para testes e desenvolvimento.

```powershell
# 1. Configuração rápida HTTP
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType http -User "testuser" -Port 5985

# 2. Verificar status
.\winrmconfig_v2.2.ps1 -Action Status

# 3. Gerar relatório
.\winrmconfig_v2.2.ps1 -Action Report
```

### Cenário 3: Troubleshooting e Diagnóstico

**Objetivo**: Diagnosticar problemas em ambiente WinRM existente.

```powershell
# 1. Verificar status atual
.\winrmconfig_v2.2.ps1 -Action Status

# 2. Verificar permissões
.\winrmconfig_v2.2.ps1 -Action CheckPermissions -User "domain\user"

# 3. Listar certificados
.\winrmconfig_v2.2.ps1 -Action ShowAllCerts

# 4. Gerar relatório detalhado
.\winrmconfig_v2.2.ps1 -Action Report

# 5. Verificar firewall
.\winrmconfig_v2.2.ps1 -Action ConfigureFirewall
```

### Cenário 4: Migração e Atualização

**Objetivo**: Migrar de configuração antiga para nova versão.

```powershell
# 1. Backup da configuração atual
.\winrmconfig_v2.2.ps1 -Action Report > backup-config.txt

# 2. Remover configuração antiga
.\winrmconfig_v2.2.ps1 -Action Disable -User "*"

# 3. Configurar nova versão
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType https -User "domain\user"

# 4. Verificar migração
.\winrmconfig_v2.2.ps1 -Action Status
```

---

## 🛡️ Segurança e Boas Práticas

### Configuração HTTPS

#### ✅ Certificados Recomendados
- **Server Authentication EKU** obrigatório
- **Validade adequada** (mínimo 1 ano)
- **Thumbprint correto** para identificação
- **Certificado confiável** pela CA

#### ✅ Configuração Segura
```powershell
# Usar certificados com Server Authentication EKU
.\winrmconfig_v2.2.ps1 -Action ShowAllCerts

# Configurar HTTPS com certificado válido
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType https -User "domain\user" -ThumbPrint "VALID_THUMBPRINT"
```

### Autenticação

#### ✅ Tipos de Autenticação
- **Kerberos**: Recomendado para ambientes de domínio
- **Negotiate**: Fallback automático
- **Basic**: Apenas para desenvolvimento/teste

#### ✅ Configuração de Usuários
```powershell
# Verificar permissões antes da configuração
.\winrmconfig_v2.2.ps1 -Action CheckPermissions -User "domain\user"

# Usar contas de serviço dedicadas
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType https -User "wec-service@domain.com"
```

### Firewall

#### ✅ Regras Específicas
- **IPs específicos** para comunicação WEC
- **Portas padrão** (5985 HTTP, 5986 HTTPS)
- **Perfis de rede** adequados (Domain/Private)

#### ✅ Monitoramento
```powershell
# Verificar regras de firewall
.\winrmconfig_v2.2.ps1 -Action ConfigureFirewall

# Monitorar status regularmente
.\winrmconfig_v2.2.ps1 -Action Status
```

### Políticas WinRM

#### ✅ Configurações Recomendadas
- **Allow Basic Authentication**: Habilitado (se necessário)
- **Allow Unencrypted Traffic**: Desabilitado
- **Allow Remote Server Management**: Configurado
- **Configure Log Access**: Configurado com SID específico

#### ✅ Aplicação de Políticas
```powershell
# Configurar políticas automaticamente
.\winrmconfig_v2.2.ps1 -Action ConfigurePolicies

# Verificar configuração
.\winrmconfig_v2.2.ps1 -Action Status
```

---

## 🔍 Troubleshooting

### Problemas Comuns

#### ❌ "Script requires elevation"
**Causa**: Execução sem privilégios administrativos
**Solução**:
```powershell
# Execute o PowerShell como Administrador
# Clique com botão direito → "Executar como Administrador"
```

#### ❌ "User not found"
**Causa**: Usuário especificado não existe
**Solução**:
```powershell
# Verificar usuário local
Get-LocalUser -Name "username"

# Verificar usuário de domínio
Get-ADUser -Identity "username"

# Usar formato correto
.\winrmconfig_v2.2.ps1 -Action CheckPermissions -User "domain\user"
```

#### ❌ "Certificate not found"
**Causa**: Certificado não encontrado ou inválido
**Solução**:
```powershell
# Listar certificados disponíveis
.\winrmconfig_v2.2.ps1 -Action ShowAllCerts

# Verificar certificados no store
Get-ChildItem Cert:\LocalMachine\My

# Usar thumbprint correto
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType https -ThumbPrint "CORRECT_THUMBPRINT"
```

#### ❌ "Firewall rule failed"
**Causa**: Problemas com regras de firewall
**Solução**:
```powershell
# Verificar perfil de rede
Get-NetConnectionProfile

# Configurar firewall interativamente
.\winrmconfig_v2.2.ps1 -Action ConfigureFirewall

# Verificar regras existentes
Get-NetFirewallRule -DisplayName "*WinRM*"
```

#### ❌ "WinRM service not running"
**Causa**: Serviço WinRM não iniciado
**Solução**:
```powershell
# Verificar status do serviço
Get-Service WinRM

# Iniciar serviço manualmente
Start-Service WinRM

# Configurar automaticamente
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType http -User "domain\user"
```

### Logs e Diagnóstico

#### 📜 Arquivos de Log
- **Localização**: `.\log\winrmconfig_YYYYMMDD.log`
- **Rotação**: Automática diária
- **Níveis**: Error, Warning, Info, Debug

#### 🔍 Habilitar Logging Debug
```powershell
# Executar com logging debug
.\winrmconfig_v2.2.ps1 -Action Enable -LogLevel Debug -User "domain\user"
```

#### 📊 Análise de Logs
```powershell
# Verificar logs recentes
Get-Content .\log\winrmconfig_*.log | Select-Object -Last 50

# Filtrar por nível
Get-Content .\log\winrmconfig_*.log | Where-Object {$_ -match "ERROR"}

# Analisar configuração
.\winrmconfig_v2.2.ps1 -Action Report
```

### Testes de Conectividade

#### 🔗 Testar WinRM
```powershell
# Testar configuração WinRM
winrm get winrm/config

# Testar listeners
winrm enumerate winrm/config/listener

# Testar conectividade
winrm identify -r:http://localhost:5985
```

#### 🔗 Testar WEC
```powershell
# Testar do servidor WEC
wecutil qc /q

# Testar do cliente
winrm identify -r:https://wec-server:5986
```

#### 🔗 Testar Certificados
```powershell
# Verificar certificados
Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*server*"}

# Testar certificado específico
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq "THUMBPRINT"}
$cert | Format-List
```

---

## 📚 Exemplos Avançados

### Exemplo 1: Configuração Multi-Servidor

**Objetivo**: Configurar múltiplos servidores para coleta centralizada.

```powershell
# Script para múltiplos servidores
$servers = @("server1", "server2", "server3")
$user = "wec-collector@domain.com"

foreach ($server in $servers) {
    Write-Host "Configurando $server..." -ForegroundColor Green
    
    # Configurar WinRM
    Invoke-Command -ComputerName $server -ScriptBlock {
        .\winrmconfig_v2.2.ps1 -Action Enable -ListenerType https -User $using:user
    }
    
    # Verificar configuração
    Invoke-Command -ComputerName $server -ScriptBlock {
        .\winrmconfig_v2.2.ps1 -Action Status
    }
}
```

### Exemplo 2: Monitoramento Automatizado

**Objetivo**: Script de monitoramento contínuo.

```powershell
# Script de monitoramento
while ($true) {
    $status = .\winrmconfig_v2.2.ps1 -Action Status
    
    if ($status -match "Inactive") {
        Write-Host "WinRM inativo detectado - reconfigurando..." -ForegroundColor Yellow
        .\winrmconfig_v2.2.ps1 -Action Enable -ListenerType http -User "domain\user"
    }
    
    Start-Sleep -Seconds 300  # Verificar a cada 5 minutos
}
```

### Exemplo 3: Backup e Restore

**Objetivo**: Backup automático da configuração.

```powershell
# Backup da configuração
$backupDate = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = ".\backup\winrm_config_$backupDate.json"

# Gerar backup
.\winrmconfig_v2.2.ps1 -Action Report | Out-File $backupFile

# Restore (exemplo)
$config = Get-Content $backupFile | ConvertFrom-Json
# Aplicar configuração restaurada...
```

### Exemplo 4: Integração com WEC

**Objetivo**: Configuração completa WEC + WinRM.

```powershell
# 1. Configurar WinRM no servidor de eventos
.\winrmconfig_v2.2.ps1 -Action Enable -ListenerType https -User "wec-collector@domain.com"

# 2. Exportar certificado
.\winrmconfig_v2.2.ps1 -Action ExportCACert -ExportCertPath "C:\WEC\ca-cert.cer"

# 3. Configurar WEC (exemplo)
wecutil cs subscription.xml

# 4. Verificar configuração
.\winrmconfig_v2.2.ps1 -Action Status
.\winrmconfig_v2.2.ps1 -Action Report
```

---

## 📞 Suporte e Contribuição

### 👨‍💻 Informações do Autor

- **Nome**: Andre Henrique (Uniao Geek)
- **Email**: contato@uniaogeek.com.br
- **LinkedIn**: [@mrhenrike](https://www.linkedin.com/in/mrhenrike)
- **Instagram**: [@uniaogeek](https://instagram.com/uniaogeek)
- **GitHub**: [@mrhenrike](https://github.com/mrhenrike)

### 🔗 Repositório

- **GitHub**: [WinRM-Log-Collector](https://github.com/mrhenrike/WinRM-Log-Collector)
- **Issues**: [Reportar problemas](https://github.com/mrhenrike/WinRM-Log-Collector/issues)
- **Discussions**: [Discussões e sugestões](https://github.com/mrhenrike/WinRM-Log-Collector/discussions)

### 📚 Documentação

- **README (PT-BR)**: [README.md](README.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **License**: [MIT License](LICENSE)

### 🤝 Contribuição

Contribuições são bem-vindas! Para contribuir:

1. **Fork** o repositório
2. **Crie** uma branch para sua feature
3. **Commit** suas mudanças
4. **Push** para a branch
5. **Abra** um Pull Request

### 🐛 Reportar Bugs

Para reportar bugs:

1. Use o [sistema de Issues](https://github.com/mrhenrike/WinRM-Log-Collector/issues)
2. Inclua informações detalhadas:
   - Sistema operacional
   - Versão do PowerShell
   - Comando executado
   - Mensagem de erro completa
   - Logs relevantes

---

## 📋 Histórico de Versões

### v2.2.0 (Atual) - 2025-10-09

#### ✨ Novas Funcionalidades
- ✅ **Testes Completos**: Validação linha por linha de todas as funcionalidades
- ✅ **Logs Aprimorados**: Sistema de logging com componentes e níveis detalhados
- ✅ **Interface Interativa**: Menus interativos para ConfigureFirewall e Disable
- ✅ **Validação de Usuários**: Verificação robusta de usuários locais e AD
- ✅ **Relatórios Detalhados**: Análise completa do sistema com recomendações
- ✅ **Tratamento de Erros**: Tratamento robusto de exceções e avisos

#### 🔧 Melhorias
- ✅ **Correção de Referências**: Todas as referências atualizadas para v2.2
- ✅ **Validação de Certificados**: Listagem organizada por categoria EKU
- ✅ **Políticas WinRM**: Configuração automática de políticas ideais
- ✅ **Firewall Management**: Interface interativa para gerenciamento de regras
- ✅ **Documentação**: README atualizado com Quick Reference

#### 🐛 Correções
- ✅ **Help Commands**: Referências de versão corrigidas
- ✅ **Logging System**: Componentes e níveis de log organizados
- ✅ **Error Handling**: Tratamento melhorado de exceções de rede
- ✅ **User Validation**: Validação aprimorada de usuários built-in

---

#### 🐛 Correções
- ✅ **Parsing de Usuários**: Suporte a múltiplos formatos
- ✅ **Configuração de Políticas**: Aplicação correta de políticas WinRM
- ✅ **Gerenciamento de Firewall**: Interface melhorada
- ✅ **Verificação de Certificados**: Análise precisa de EKU

### v2.0.0 - 2024-12-15

#### ✨ Funcionalidades
- ✅ Consolidação de scripts originais
- ✅ Sistema de logging aprimorado
- ✅ Configuração de firewall
- ✅ Gerenciamento de certificados
- ✅ Documentação básica

### v1.23 - 2024-11-20

#### ✨ Funcionalidades
- ✅ Configuração básica de firewall
- ✅ Funcionalidade limitada

### v1.0 - 2024-10-01

#### ✨ Lançamento
- ✅ Lançamento inicial
- ✅ Configuração básica WinRM

---

## 📄 Licença

Este projeto está licenciado sob a [MIT License](LICENSE) - veja o arquivo LICENSE para detalhes.

---

## 🙏 Agradecimentos

- **Microsoft** - Por fornecer a documentação WinRM
- **Comunidade PowerShell** - Por feedback e sugestões
- **Contribuidores** - Por melhorias e correções
- **Usuários** - Por relatórios de bugs e sugestões

---

**Feito com ❤️ por [Uniao Geek](https://github.com/mrhenrike)**

*Para mais informações, visite: [uniaogeek.com.br](https://uniaogeek.com.br)*