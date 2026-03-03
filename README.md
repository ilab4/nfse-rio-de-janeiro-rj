# NFSe Rio de Janeiro - RJ (Padrão Nacional ADN)

Integração completa para **emitir, consultar e cancelar NFS-e no município do Rio de Janeiro -- RJ**, utilizando o novo **Padrão Nacional (ADN)** via API REST com mTLS.

------------------------------------------------------------------------

## 📌 Sobre a Prefeitura e a Migração

-   **Município:** Rio de Janeiro -- RJ
-   **Código IBGE:** 3304557
-   **Provedor:** Emissor Nacional (ADN - Ambiente de Dados Nacional)
-   **Status:** A "Nota Carioca" foi descontinuada para a maioria dos serviços, sendo substituída pelo padrão nacional.
-   **API Produção:** `https://sefin.nfse.gov.br/SefinNacional`
-   **API Homologação:** `https://sefin.producaorestrita.nfse.gov.br/SefinNacional`

------------------------------------------------------------------------

## 🎯 Para quem é este projeto?

-   Desenvolvedores que precisam adaptar sistemas do Rio de Janeiro para o novo padrão nacional.
-   Sistemas SaaS que buscam integração direta com a API REST do Serpro/Receita Federal.
-   Empresas que precisam emitir notas via API enviando DPS (Declaração de Prestação de Serviços).

------------------------------------------------------------------------

## 🚀 Funcionalidades

Este projeto implementa o fluxo completo exigido pelo Portal Nacional:

-   ✅ **Gerar DPS:** Montagem do XML da Declaração de Prestação de Serviços (v1.01).
-   ✅ **Assinatura Digital:** Assinatura manual do XML utilizando XML-DSig (SHA-256) na tag `infDPS`.
-   ✅ **Compactação ADN:** Compactação GZip e codificação Base64 do XML (requisito obrigatório da API).
-   ✅ **Comunicação mTLS:** Envio via cURL utilizando certificado digital A1 para autenticação mTLS.
-   ✅ **Consulta por Chave:** Recuperação de notas já emitidas e processadas.
-   ✅ **Cancelamento por Evento:** Registro de evento de cancelamento assinado e compactado.

------------------------------------------------------------------------

## 🛠 Requisitos

-   **PHP 7.4+**
-   **Extensões:**
    -   `openssl` (para leitura do certificado e assinatura)
    -   `curl` (para comunicação com a API REST)
    -   `zlib` (para compactação GZip)
-   **Certificado digital A1** (.pfx)

------------------------------------------------------------------------

## ⚠️ Aviso Importante

Desde **Janeiro de 2026**, o Rio de Janeiro utiliza o Emissor Nacional. Diferente do padrão ABRASF (SOAP), o padrão nacional utiliza **API REST** onde o XML é enviado compactado dentro de um campo JSON (`dpsXmlGZipB64`).

Sempre valide:
-   **Código de Tributação Nacional:** Deve seguir a lista da LC 116 nacional (6 dígitos).
-   **Regime Especial:** Verifique se a empresa é optante pelo Simples Nacional para preencher corretamente o grupo `regTrib`.

------------------------------------------------------------------------

## 💼 Precisa integrar NFSe em outros municípios?

A **ILAB4** desenvolve integrações sob demanda para qualquer cidade do
Brasil.

👉 https://ilab4.me

------------------------------------------------------------------------

## 🤝 Contribuição

Se este projeto ajudou na sua migração para o padrão nacional do RJ:

⭐ Deixe uma estrela  
🔁 Partilhe para ajudar outros desenvolvedores  
💬 Entre em contacto para projetos personalizados