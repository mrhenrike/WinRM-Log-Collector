# WinRM Log Collector v2.0

## 🚀 Início Rápido

### 1. Download e Execução
```powershell
# Download do script
git clone https://github.com/mrhenrike/WinRM-Log-Collector.git
cd WinRM-Log-Collector

# Executar como Administrador
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -User "seu_usuario" -AuthType basic
```

### 2. Verificar Configuração
```powershell
.\winrmconfig_v2.0.ps1 -Action status
```

### 3. Gerar Relatório
```powershell
.\winrmconfig_v2.0.ps1 -Action report
```

## 📖 Guia Completo

### Pré-requisitos
- ✅ PowerShell 5.1 ou superior
- ✅ Privilégios administrativos
- ✅ Windows Server 2008 R2 ou superior

### Formatos de Usuário Suportados
O script aceita usuários em múltiplos formatos:
- `domain\user` (ex: `CONTOSO\joao.silva`)
- `user@domain.com` (ex: `joao.silva@contoso.com`)
- `localuser` (ex: `administrator`)

## 🎯 Ações Disponíveis

### 1. **report** - Gerar Relatório de Configuração
```powershell
# Relatório básico
.\winrmconfig_v2.0.ps1 -Action report

# Relatório para usuário específico
.\winrmconfig_v2.0.ps1 -Action report -User "domain\user"
```

### 2. **enable** - Configurar Listeners WinRM
```powershell
# Listener HTTP com autenticação básica
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -User "domain\user" -AuthType basic

# Listener HTTPS com certificado
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType https -User "domain\user" -ThumbPrint "ABC123..."

# Porta personalizada
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -Port 5985 -User "domain\user"
```

### 3. **configurefirewall** - Configurar Regras de Firewall
```powershell
# Configurar firewall para WEC
.\winrmconfig_v2.0.ps1 -Action configurefirewall -WECIP "192.168.1.100" -WECHostname "wec-server"
```

### 4. **exportcacert** - Exportar Certificado
```powershell
# Exportar certificado para caminho específico
.\winrmconfig_v2.0.ps1 -Action exportcacert -ExportCertPath "C:\temp"
```

### 5. **showallcerts** - Listar Certificados Compatíveis
```powershell
# Mostrar todos os certificados disponíveis
.\winrmconfig_v2.0.ps1 -Action showallcerts
```

### 6. **disable** - Remover Listeners WinRM
```powershell
# Remover listener HTTP
.\winrmconfig_v2.0.ps1 -Action disable -ListenerType http

# Remover listener HTTPS
.\winrmconfig_v2.0.ps1 -Action disable -ListenerType https
```

### 7. **status** - Verificar Status do Serviço WinRM
```powershell
# Verificar status atual
.\winrmconfig_v2.0.ps1 -Action status
```

## 🎯 Cenários Práticos

### Cenário 1: Configuração Completa WEC (HTTPS + Firewall + Certificado)
```powershell
# Passo 1: Configurar listener HTTPS
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType https -User "wec-collector@domain.com"

# Passo 2: Configurar firewall
.\winrmconfig_v2.0.ps1 -Action configurefirewall -WECIP "192.168.1.100" -WECHostname "wec-server"

# Passo 3: Exportar certificado
.\winrmconfig_v2.0.ps1 -Action exportcacert -ExportCertPath "C:\temp"
```

### Cenário 2: Configuração para Desenvolvimento/Teste (HTTP + Basic Auth)
```powershell
# Configuração rápida HTTP para testes
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -AuthType basic -User "testuser"
```

### Cenário 3: Troubleshooting e Verificação
```powershell
# Verificar status
.\winrmconfig_v2.0.ps1 -Action status

# Gerar relatório detalhado
.\winrmconfig_v2.0.ps1 -Action report -User "domain\user"

# Listar certificados disponíveis
.\winrmconfig_v2.0.ps1 -Action showallcerts
```

## ⚙️ Referência de Parâmetros

| Parâmetro | Tipo | Descrição | Exemplo |
|-----------|------|-----------|---------|
| `-Action` | String | Ação a executar | `report`, `enable`, `configurefirewall` |
| `-ListenerType` | String | Tipo de listener | `http`, `https` |
| `-User` | String | Conta de usuário | `domain\user`, `user@domain.com` |
| `-Port` | Integer | Porta personalizada (1-65535) | `5985`, `5986` |
| `-ThumbPrint` | String | Thumbprint do certificado | `ABC123...` |
| `-ExportCertPath` | String | Caminho para exportar | `C:\temp` |
| `-AuthType` | String | Tipo de autenticação | `basic`, `kerberos` |
| `-WECIP` | String | IP do WEC | `192.168.1.100` |
| `-WECHostname` | String | Hostname do WEC | `wec-server` |
| `-LogLevel` | String | Nível de log | `Error`, `Warning`, `Info`, `Debug` |
| `-ConfigFile` | String | Arquivo de configuração | `config.json` |

## 🔍 Logging e Troubleshooting

### Arquivos de Log
- **Localização**: `%TEMP%\winrmconfig_enhanced.log`
- **Níveis**: Error, Warning, Info, Debug
- **Rotação**: Automática (mantém últimos 10 arquivos)

### Habilitar Logging Debug
```powershell
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -LogLevel Debug
```

### Problemas Comuns e Soluções

#### Problema 1: "Script requires elevation"
**Solução**: Execute o PowerShell como Administrador
```powershell
# Clique com botão direito no PowerShell → "Executar como Administrador"
```

#### Problema 2: "Listener already exists"
**Solução**: O script automaticamente gerencia listeners existentes
```powershell
# O script configurará listeners existentes em vez de criar novos
```

#### Problema 3: "Certificate not found"
**Solução**: Verificar certificados disponíveis
```powershell
.\winrmconfig_v2.0.ps1 -Action showallcerts
```

#### Problema 4: "Firewall rule failed"
**Solução**: Verificar perfil de rede
```powershell
# Certifique-se de que o perfil de rede é "Domain" ou "Private"
# Redes públicas podem bloquear regras de firewall
```

## 🧪 Testes de Conectividade

### Testar Conectividade WinRM
```powershell
# Testar HTTP
winrm get winrm/config/listener?Address=*+Transport=HTTP

# Testar HTTPS
winrm get winrm/config/listener?Address=*+Transport=HTTPS
```

### Testar Conectividade WEC
```powershell
# Testar do servidor WEC
wecutil qc /q

# Testar do cliente
winrm identify -r:https://wec-server:5986
```

### Testar Certificado
```powershell
# Verificar validade do certificado
Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*seu-servidor*"}
```

## 📚 Exemplos Completos

### Exemplo 1: Configuração Corporativa WEC
```powershell
# 1. Configurar listener HTTPS para WEC
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType https -User "wec-collector@contoso.com"

# 2. Configurar firewall para servidor WEC
.\winrmconfig_v2.0.ps1 -Action configurefirewall -WECIP "10.0.1.100" -WECHostname "wec-contoso"

# 3. Exportar certificado para configuração WEC
.\winrmconfig_v2.0.ps1 -Action exportcacert -ExportCertPath "C:\WEC\Certificates"

# 4. Verificar configuração
.\winrmconfig_v2.0.ps1 -Action status
.\winrmconfig_v2.0.ps1 -Action report
```

### Exemplo 2: Ambiente de Desenvolvimento
```powershell
# 1. Configuração rápida HTTP para desenvolvimento
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -AuthType basic -User "devuser"

# 2. Verificar status
.\winrmconfig_v2.0.ps1 -Action status

# 3. Gerar relatório
.\winrmconfig_v2.0.ps1 -Action report -User "devuser"
```

### Exemplo 3: Troubleshooting
```powershell
# 1. Verificar status atual
.\winrmconfig_v2.0.ps1 -Action status

# 2. Listar certificados disponíveis
.\winrmconfig_v2.0.ps1 -Action showallcerts

# 3. Gerar relatório detalhado
.\winrmconfig_v2.0.ps1 -Action report -User "domain\user" -LogLevel Debug

# 4. Verificar configuração de firewall
.\winrmconfig_v2.0.ps1 -Action configurefirewall -WECIP "192.168.1.100" -WECHostname "wec-server"
```

## 🛡️ Considerações de Segurança

### Configuração HTTPS
- ✅ Use certificados válidos com EKU Server Authentication
- ✅ Configure thumbprint correto do certificado
- ✅ Habilite listeners HTTPS para produção

### Autenticação
- ✅ Use autenticação Kerberos para ambientes de domínio
- ✅ Use autenticação Basic apenas para teste/desenvolvimento
- ✅ Configure permissões adequadas de usuário

### Firewall
- ✅ Configure faixas de IP específicas para comunicação WEC
- ✅ Use perfis de rede privada/domínio
- ✅ Monitore regras de firewall regularmente

## 📞 Suporte

### Informações do Autor
- **Autor**: Andre Henrique (Uniao Geek)
- **Email**: contato@uniaogeek.com.br
- **LinkedIn/X**: [@mrhenrike](https://www.linkedin.com/in/mrhenrike)
- **Instagram**: [@uniaogeek](https://instagram.com/uniaogeek)

### Repositório
- **GitHub**: [https://github.com/mrhenrike/WinRM-Log-Collector](https://github.com/mrhenrike/WinRM-Log-Collector)
- **Issues**: [Reportar problemas aqui](https://github.com/mrhenrike/WinRM-Log-Collector/issues)

### Documentação
- **README (PT-BR)**: [README.md](README.md)
- **README (EN-US)**: [README_EN.md](README_EN.md)

---

## 📋 Histórico de Versões

### v2.0.0 (Atual)
- ✅ Consolidação de todas as funções dos scripts originais
- ✅ Tratamento de erros e logging aprimorados
- ✅ Sistema de ajuda abrangente
- ✅ Parsing de formato de usuário melhorado
- ✅ Configuração de firewall adicionada
- ✅ Gerenciamento de certificados aprimorado
- ✅ Testes de conectividade adicionados
- ✅ Documentação completa

### v1.23
- ✅ Configuração básica de firewall
- ✅ Funcionalidade limitada

### v1.0
- ✅ Lançamento inicial
- ✅ Configuração básica WinRM

---

**Feito com ❤️ por [Uniao Geek](https://github.com/mrhenrike)**