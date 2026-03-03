# chat-e2ee

## Política de Validação de Chaves

O módulo `key_policy.py` implementa uma política de validação de chaves PGP que é aplicada automaticamente antes de criptografar ou assinar mensagens. A política verifica:

| Verificação | Padrão | Descrição |
|---|---|---|
| Revogação | Rejeitar | Chaves revogadas são rejeitadas |
| Expiração | Rejeitar | Chaves expiradas são rejeitadas |
| Sem expiração | Permitir | Chaves sem data de expiração são aceitas |
| Confiança mínima | `marginal` | Nível mínimo de confiança exigido |
| Idade máxima | 365 dias | Chaves mais antigas são rejeitadas |

### Configuração

A política pode ser personalizada alterando o dicionário `POLITICA_PADRAO` em `key_policy.py`:

```python
POLITICA_PADRAO = {
    "confianca_minima": "marginal",
    "max_idade_chave_dias": 365,
    "permitir_chaves_sem_expiracao": True,
    "rejeitar_chaves_revogadas": True,
    "rejeitar_chaves_expiradas": True,
}
```

### Testes

```bash
python3 -m unittest test_key_policy -v
```
