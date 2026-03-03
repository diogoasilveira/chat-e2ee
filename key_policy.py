"""
Módulo de Política de Validação de Chaves PGP.

Define regras para validar chaves antes de usá-las para criptografia
ou verificação de assinaturas no chat E2EE.

Políticas verificadas:
  - Expiração da chave
  - Revogação da chave
  - Nível mínimo de confiança (trust level)
  - Idade máxima permitida da chave
"""

import time

# Níveis de confiança do GPG ordenados por prioridade
NIVEIS_CONFIANCA = {
    "expired":   -1,
    "undefined": 0,
    "never":     0,
    "unknown":   0,
    "marginal":  1,
    "full":      2,
    "ultimate":  3,
}

# Configuração padrão da política
POLITICA_PADRAO = {
    "confianca_minima": "marginal",         # Nível mínimo de confiança aceitável
    "max_idade_chave_dias": 365,            # Idade máxima da chave em dias (0 = sem limite)
    "permitir_chaves_sem_expiracao": True,   # Permitir chaves sem data de expiração
    "rejeitar_chaves_revogadas": True,       # Rejeitar automaticamente chaves revogadas
    "rejeitar_chaves_expiradas": True,       # Rejeitar automaticamente chaves expiradas
}


class ResultadoValidacao:
    """Resultado da validação de uma chave."""

    def __init__(self, valida, motivo=""):
        self.valida = valida
        self.motivo = motivo

    def __bool__(self):
        return self.valida

    def __repr__(self):
        estado = "VÁLIDA" if self.valida else "INVÁLIDA"
        return f"ResultadoValidacao({estado}, motivo='{self.motivo}')"


def _valor_confianca(nivel):
    """Retorna o valor numérico de um nível de confiança."""
    if isinstance(nivel, str):
        return NIVEIS_CONFIANCA.get(nivel.lower(), -1)
    return -1


def validar_chave(info_chave, politica=None):
    """
    Valida uma chave PGP de acordo com a política configurada.

    Parâmetros
    ----------
    info_chave : dict
        Dicionário com informações da chave (conforme retornado por gpg.list_keys()).
        Campos esperados: 'trust', 'expires', 'date', 'fingerprint', 'uids'.
    politica : dict, opcional
        Dicionário com as regras da política. Se não informado, usa POLITICA_PADRAO.

    Retorna
    -------
    ResultadoValidacao
        Objeto indicando se a chave é válida e o motivo em caso de rejeição.
    """
    if politica is None:
        politica = POLITICA_PADRAO

    fingerprint = info_chave.get("fingerprint", "desconhecida")

    # 1. Verificar revogação
    if politica.get("rejeitar_chaves_revogadas", True):
        trust = info_chave.get("trust", "")
        if trust == "r":
            return ResultadoValidacao(
                False,
                f"Chave {fingerprint} foi revogada."
            )

    # 2. Verificar expiração
    if politica.get("rejeitar_chaves_expiradas", True):
        expires = info_chave.get("expires", "")
        if expires:
            try:
                ts_expiracao = int(expires)
                if ts_expiracao > 0 and ts_expiracao < time.time():
                    return ResultadoValidacao(
                        False,
                        f"Chave {fingerprint} expirou."
                    )
            except (ValueError, TypeError):
                pass

    # 3. Verificar se chave sem expiração é permitida
    if not politica.get("permitir_chaves_sem_expiracao", True):
        expires = info_chave.get("expires", "")
        if not expires:
            return ResultadoValidacao(
                False,
                f"Chave {fingerprint} não possui data de expiração e a política exige expiração."
            )

    # 4. Verificar nível de confiança
    confianca_minima = politica.get("confianca_minima", "marginal")
    ownertrust = info_chave.get("ownertrust", "")
    if ownertrust:
        valor_chave = _valor_confianca(ownertrust)
        valor_minimo = _valor_confianca(confianca_minima)
        if valor_chave < valor_minimo:
            return ResultadoValidacao(
                False,
                f"Chave {fingerprint} possui nível de confiança '{ownertrust}' "
                f"abaixo do mínimo exigido '{confianca_minima}'."
            )

    # 5. Verificar idade máxima da chave
    max_dias = politica.get("max_idade_chave_dias", 0)
    if max_dias > 0:
        data_criacao = info_chave.get("date", "")
        if data_criacao:
            try:
                ts_criacao = int(data_criacao)
                idade_segundos = time.time() - ts_criacao
                idade_dias = idade_segundos / 86400
                if idade_dias > max_dias:
                    return ResultadoValidacao(
                        False,
                        f"Chave {fingerprint} tem {int(idade_dias)} dias, "
                        f"excedendo o máximo de {max_dias} dias."
                    )
            except (ValueError, TypeError):
                pass

    return ResultadoValidacao(True, "Chave aprovada pela política.")


def buscar_chave_por_uid(gpg, uid):
    """
    Busca uma chave pública no keyring pelo UID (nome de usuário ou e-mail).

    Retorna a primeira chave que contém o UID no campo 'uids', ou None.
    """
    chaves = gpg.list_keys()
    for chave in chaves:
        for u in chave.get("uids", []):
            if uid.lower() in u.lower():
                return chave
    return None


def validar_destinatario(gpg, destinatario, politica=None):
    """
    Valida a chave pública de um destinatário antes de enviar uma mensagem.

    Parâmetros
    ----------
    gpg : gnupg.GPG
        Instância do GPG.
    destinatario : str
        Nome de usuário ou e-mail do destinatário.
    politica : dict, opcional
        Política de validação a ser usada.

    Retorna
    -------
    ResultadoValidacao
        Resultado da validação.
    """
    chave = buscar_chave_por_uid(gpg, destinatario)
    if chave is None:
        return ResultadoValidacao(
            False,
            f"Chave pública do destinatário '{destinatario}' não encontrada no keyring."
        )
    return validar_chave(chave, politica)


def validar_remetente(gpg, remetente, politica=None):
    """
    Valida a chave privada do remetente antes de assinar uma mensagem.

    Parâmetros
    ----------
    gpg : gnupg.GPG
        Instância do GPG.
    remetente : str
        Nome de usuário ou e-mail do remetente.
    politica : dict, opcional
        Política de validação a ser usada.

    Retorna
    -------
    ResultadoValidacao
        Resultado da validação.
    """
    chaves = gpg.list_keys(True)  # True = chaves privadas
    for chave in chaves:
        for u in chave.get("uids", []):
            if remetente.lower() in u.lower():
                return validar_chave(chave, politica)
    return ResultadoValidacao(
        False,
        f"Chave privada do remetente '{remetente}' não encontrada no keyring."
    )
