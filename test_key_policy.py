"""
Testes unitários para o módulo key_policy (Política de Validação de Chaves).
"""

import time
import unittest

from key_policy import (
    POLITICA_PADRAO,
    ResultadoValidacao,
    _valor_confianca,
    buscar_chave_por_uid,
    validar_chave,
)


class TestResultadoValidacao(unittest.TestCase):
    """Testes para a classe ResultadoValidacao."""

    def test_resultado_valido(self):
        r = ResultadoValidacao(True, "ok")
        self.assertTrue(r.valida)
        self.assertTrue(bool(r))
        self.assertIn("VÁLIDA", repr(r))

    def test_resultado_invalido(self):
        r = ResultadoValidacao(False, "expirada")
        self.assertFalse(r.valida)
        self.assertFalse(bool(r))
        self.assertIn("INVÁLIDA", repr(r))


class TestValorConfianca(unittest.TestCase):
    """Testes para a conversão de níveis de confiança."""

    def test_niveis_conhecidos(self):
        self.assertEqual(_valor_confianca("ultimate"), 3)
        self.assertEqual(_valor_confianca("full"), 2)
        self.assertEqual(_valor_confianca("marginal"), 1)
        self.assertEqual(_valor_confianca("undefined"), 0)
        self.assertEqual(_valor_confianca("expired"), -1)

    def test_nivel_desconhecido(self):
        self.assertEqual(_valor_confianca("invalido"), -1)

    def test_case_insensitive(self):
        self.assertEqual(_valor_confianca("ULTIMATE"), 3)
        self.assertEqual(_valor_confianca("Full"), 2)

    def test_tipo_invalido(self):
        self.assertEqual(_valor_confianca(123), -1)
        self.assertEqual(_valor_confianca(None), -1)


class TestValidarChave(unittest.TestCase):
    """Testes para a função validar_chave."""

    def _chave_valida(self, **overrides):
        """Cria um dicionário de chave válida com valores padrão."""
        chave = {
            "fingerprint": "ABCD1234",
            "trust": "f",
            "ownertrust": "full",
            "expires": str(int(time.time()) + 86400 * 30),  # expira em 30 dias
            "date": str(int(time.time()) - 86400 * 10),     # criada há 10 dias
            "uids": ["alice <alice@example.com>"],
        }
        chave.update(overrides)
        return chave

    # -- Chave válida --
    def test_chave_valida_aprovada(self):
        resultado = validar_chave(self._chave_valida())
        self.assertTrue(resultado)
        self.assertIn("aprovada", resultado.motivo)

    # -- Revogação --
    def test_chave_revogada_rejeitada(self):
        chave = self._chave_valida(trust="r")
        resultado = validar_chave(chave)
        self.assertFalse(resultado)
        self.assertIn("revogada", resultado.motivo)

    def test_chave_revogada_permitida_se_politica_desativada(self):
        chave = self._chave_valida(trust="r")
        politica = {**POLITICA_PADRAO, "rejeitar_chaves_revogadas": False}
        resultado = validar_chave(chave, politica)
        self.assertTrue(resultado)

    # -- Expiração --
    def test_chave_expirada_rejeitada(self):
        chave = self._chave_valida(expires=str(int(time.time()) - 86400))
        resultado = validar_chave(chave)
        self.assertFalse(resultado)
        self.assertIn("expirou", resultado.motivo)

    def test_chave_expirada_permitida_se_politica_desativada(self):
        chave = self._chave_valida(expires=str(int(time.time()) - 86400))
        politica = {**POLITICA_PADRAO, "rejeitar_chaves_expiradas": False}
        resultado = validar_chave(chave, politica)
        self.assertTrue(resultado)

    # -- Sem expiração --
    def test_chave_sem_expiracao_permitida_por_padrao(self):
        chave = self._chave_valida(expires="")
        resultado = validar_chave(chave)
        self.assertTrue(resultado)

    def test_chave_sem_expiracao_rejeitada_se_politica_exige(self):
        chave = self._chave_valida(expires="")
        politica = {**POLITICA_PADRAO, "permitir_chaves_sem_expiracao": False}
        resultado = validar_chave(chave, politica)
        self.assertFalse(resultado)
        self.assertIn("expiração", resultado.motivo)

    # -- Confiança --
    def test_confianca_insuficiente_rejeitada(self):
        chave = self._chave_valida(ownertrust="undefined")
        politica = {**POLITICA_PADRAO, "confianca_minima": "marginal"}
        resultado = validar_chave(chave, politica)
        self.assertFalse(resultado)
        self.assertIn("confiança", resultado.motivo)

    def test_confianca_suficiente_aprovada(self):
        chave = self._chave_valida(ownertrust="full")
        politica = {**POLITICA_PADRAO, "confianca_minima": "marginal"}
        resultado = validar_chave(chave, politica)
        self.assertTrue(resultado)

    # -- Idade máxima da chave --
    def test_chave_muito_antiga_rejeitada(self):
        chave = self._chave_valida(date=str(int(time.time()) - 86400 * 400))
        politica = {**POLITICA_PADRAO, "max_idade_chave_dias": 365}
        resultado = validar_chave(chave, politica)
        self.assertFalse(resultado)
        self.assertIn("excedendo", resultado.motivo)

    def test_chave_recente_aprovada(self):
        chave = self._chave_valida(date=str(int(time.time()) - 86400 * 10))
        politica = {**POLITICA_PADRAO, "max_idade_chave_dias": 365}
        resultado = validar_chave(chave, politica)
        self.assertTrue(resultado)

    def test_idade_sem_limite(self):
        chave = self._chave_valida(date=str(int(time.time()) - 86400 * 9999))
        politica = {**POLITICA_PADRAO, "max_idade_chave_dias": 0}
        resultado = validar_chave(chave, politica)
        self.assertTrue(resultado)


class TestBuscarChavePorUid(unittest.TestCase):
    """Testes para buscar_chave_por_uid com mock do GPG."""

    def test_chave_encontrada(self):
        class FakeGPG:
            def list_keys(self):
                return [
                    {"uids": ["bob <bob@example.com>"], "fingerprint": "B0B"},
                    {"uids": ["alice <alice@example.com>"], "fingerprint": "A11CE"},
                ]

        chave = buscar_chave_por_uid(FakeGPG(), "alice")
        self.assertIsNotNone(chave)
        self.assertEqual(chave["fingerprint"], "A11CE")

    def test_chave_nao_encontrada(self):
        class FakeGPG:
            def list_keys(self):
                return [{"uids": ["bob <bob@example.com>"], "fingerprint": "B0B"}]

        chave = buscar_chave_por_uid(FakeGPG(), "charlie")
        self.assertIsNone(chave)

    def test_busca_case_insensitive(self):
        class FakeGPG:
            def list_keys(self):
                return [{"uids": ["Alice <alice@example.com>"], "fingerprint": "A11CE"}]

        chave = buscar_chave_por_uid(FakeGPG(), "ALICE")
        self.assertIsNotNone(chave)


if __name__ == "__main__":
    unittest.main()
