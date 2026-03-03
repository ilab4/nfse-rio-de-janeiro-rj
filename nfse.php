<?php
date_default_timezone_set('America/Sao_Paulo');
/**
 * ====
 * ILAB4.ME
 * NFSe - Padrão Nacional (NFS-e Nacional) - Rio de Janeiro/RJ
 * Gerar (DPS), Consultar por Chave e Cancelar (Evento)
 * ====
 * 
 * INSTRUÇÕES:
 * 1. Coloque este arquivo na raiz do seu servidor web (htdocs/www)
 * 2. Coloque o certificado digital .pfx na mesma pasta (subpasta certificates/)
 * 3. Preencha as configurações abaixo
 * 4. Acesse http://localhost/nfse_rj.php
 * 
 * IMPORTANTE:
 * Desde janeiro/2026, o Rio de Janeiro migrou para o Emissor Nacional (NFS-e Nacional).
 * A Nota Carioca foi descontinuada. A emissão agora é via API REST com mTLS,
 * enviando DPS (Declaração de Prestação de Serviços) em XML assinado, 
 * compactado (GZip) e codificado (Base64), encapsulado em JSON.
 * 
 * Referências:
 * - Portal NFS-e Nacional: https://www.gov.br/nfse/pt-br
 * - APIs: https://www.gov.br/nfse/pt-br/biblioteca/documentacao-tecnica/apis-prod-restrita-e-producao
 * - Guia migração RJ: https://nfsenacional.prefeitura.rio/
 * 
 * REQUISITOS: PHP 7.4+, extensões openssl, curl e zlib habilitadas
 * ====
 */

// ==== CONFIGURAÇÕES ====
$config = [
    'ambiente'              => 'homologacao',
    'url_producao'          => 'https://sefin.nfse.gov.br/SefinNacional',
    'url_homologacao'       => 'https://sefin.producaorestrita.nfse.gov.br/SefinNacional',
    'certificado_pfx'       => 'certificates/certificado.pfx',
    'certificado_senha'     => 'senha-do-certificado',
    'prestador_cnpj'        => 'cnpj-da-empresa',
    'prestador_im'          => 'inscrição-municipal-da-empresa',
    'prestador_razao'       => 'SUA EMPRESA',
    'prestador_nome_fantasia' => 'SUA EMPRESA',
    
    'prestador_endereco'      => 'Endereço',
    'prestador_numero'        => 'Numero',
    'prestador_complemento'   => '',
    'prestador_bairro'        => 'Bairro',
    'prestador_cep'           => 'CEP',
    'prestador_uf'            => 'RJ',
    'prestador_municipio'     => 'RIO DE JANEIRO',
    'codigo_municipio_ibge'   => '3304557',
    'codigo_pais'           => '1058',
    'dps_serie'             => '1',
    'dps_numero'            => '1',
    'dps_tipo_doc'          => '99', // 99=Outros (sem RPS físico)
    'competencia'           => '', // AAAA-MM (vazio = mês atual)
    'valor_servicos'        => '1.00',
    'codigo_trib_nacional'  => '010201', // Código Tributação Nacional (ii.ss.dd sem pontos)
    'codigo_trib_municipal' => '001',    // Complemento municipal (xxx)
    'codigo_nbs'            => '115022000',       // NBS (opcional)
    'discriminacao'         => 'Servico de teste - desenvolvimento de software',
    'codigo_municipio_ibge' => '3304557', // Rio de Janeiro
    'codigo_pais'           => '1058',    // Brasil
    // Tributação
    'iss_retido'            => false,
    'aliquota_iss'          => '2.01',    // Percentual (ex: 5.00 = 5%)
    'valor_deducoes'        => '0.00',
    'valor_desconto_incond' => '0.00',
    'valor_desconto_cond'   => '0.00',
    // Regime Especial
    'optante_simples'       => true,
    'regime_especial'       => '0', // 0=Nenhum, 1=Microempresa, 2=Estimativa, 3=Soc.Profissionais, etc.
    // Tomador
    'tomador_tipo_doc'      => '1', // 1=CPF, 2=CNPJ
    'tomador_documento'     => '99999999999',
    'tomador_razao'         => 'JOSE DA SILVA',
    'tomador_email'         => 'tomador@email.com',
    'tomador_telefone'      => '21999999999',
    'tomador_endereco'      => 'Rua Exemplo',
    'tomador_numero'        => '100',
    'tomador_complemento'   => '',
    'tomador_bairro'        => 'Centro',
    'tomador_cep'           => '21930440',
    'tomador_uf'            => 'RJ',
    'tomador_municipio'     => 'RIO DE JANEIRO',
    'tomador_cod_mun'       => '3304557',
    'tomador_cod_pais'      => '1058',
    // Consulta
    'consultar_chave_acesso' => '',
    'consultar_id_dps'       => '',
    // Cancelamento (Evento)
    'cancelar_chave_acesso'  => '',
    'cancelar_motivo'        => 'Erro na emissão',
    'regime_tributario'        => 1,
];

// ==== FUNÇÕES ====

/**
 * Extrai certificado e chave privada do .pfx
 */
/**
 * Extrai certificado e chave privada do .pfx
 */
function extrairCertificado($pfxPath, $senha) {
    if (!file_exists($pfxPath)) {
        throw new Exception("Arquivo de certificado não encontrado: $pfxPath");
    }
    $pfxContent = file_get_contents($pfxPath);
    $certs = [];
    if (!openssl_pkcs12_read($pfxContent, $certs, $senha)) {
        throw new Exception("Erro ao ler certificado PFX. Verifique a senha. OpenSSL: " . openssl_error_string());
    }
    $certPem = tempnam(sys_get_temp_dir(), 'cert_');
    $keyPem  = tempnam(sys_get_temp_dir(), 'key_');
    file_put_contents($certPem, $certs['cert']);
    file_put_contents($keyPem, $certs['pkey']);
    return [
        'cert'     => $certs['cert'],
        'pkey'     => $certs['pkey'],
        'certFile' => $certPem,
        'keyFile'  => $keyPem,
    ];
}

/**
 * Assina XML com certificado digital (XML-DSig / Enveloped Signature)
 * Padrão NFS-e Nacional: SHA-256
 */
function assinarXml($xml, $certPem, $pkeyPem, $tagToSign = 'infDPS') {
    $doc = new DOMDocument('1.0', 'UTF-8');
    $doc->preserveWhiteSpace = false;
    $doc->formatOutput = false;
    $doc->loadXML($xml);

    $node = $doc->getElementsByTagName($tagToSign)->item(0);
    if (!$node) {
        throw new Exception("Tag '$tagToSign' não encontrada no XML para assinatura.");
    }

    $id = $node->getAttribute('Id');
    if (empty($id)) {
        $id = 'DPS_' . uniqid();
        $node->setAttribute('Id', $id);
    }

    // Canonicalização C14N
    $canonicalizado = $node->C14N(false, false, null, null);
    $digestValue = base64_encode(hash('sha256', $canonicalizado, true));

    $signedInfo = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
        . '<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'
        . '<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        . '<Reference URI="#' . $id . '">'
        . '<Transforms>'
        . '<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        . '<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'
        . '</Transforms>'
        . '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        . '<DigestValue>' . $digestValue . '</DigestValue>'
        . '</Reference>'
        . '</SignedInfo>';

    $docSI = new DOMDocument('1.0', 'UTF-8');
    $docSI->loadXML($signedInfo);
    $signedInfoCanon = $docSI->documentElement->C14N(false, false, null, null);

    $privateKey = openssl_pkey_get_private($pkeyPem);
    if (!$privateKey) {
        throw new Exception("Erro ao carregar chave privada: " . openssl_error_string());
    }

    $signature = '';
    if (!openssl_sign($signedInfoCanon, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
        throw new Exception("Erro ao assinar: " . openssl_error_string());
    }
    $signatureValue = base64_encode($signature);

    $x509 = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\r", "\n"], '', $certPem);

    $signatureXml = '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">'
        . $signedInfo
        . '<SignatureValue>' . $signatureValue . '</SignatureValue>'
        . '<KeyInfo>'
        . '<X509Data>'
        . '<X509Certificate>' . $x509 . '</X509Certificate>'
        . '</X509Data>'
        . '</KeyInfo>'
        . '</Signature>';

    $docSig = new DOMDocument('1.0', 'UTF-8');
    $docSig->loadXML($signatureXml);
    $signatureNode = $doc->importNode($docSig->documentElement, true);
    $node->parentNode->appendChild($signatureNode);

    $doc->documentElement->setAttribute('versao', '1.01'); 

    $xmlFinal = $doc->saveXML();
    
    // Remove namespaces redundantes que o DOMDocument coloca nas tags filhas da Signature
    $xmlFinal = str_replace(' xmlns="http://www.w3.org/2000/09/xmldsig#"', '', $xmlFinal);
    // Restaura apenas na tag raiz da assinatura
    $xmlFinal = str_replace('<Signature>', '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">', $xmlFinal);

    return $xmlFinal;

//    return $doc->saveXML();
}

/**
 * Compacta XML com GZip e codifica em Base64
 * Formato exigido pela API ADN Nacional
 */
function compactarXmlBase64($xml) {
    $gzipped = gzencode($xml, 9);
    if ($gzipped === false) {
        throw new Exception("Erro ao compactar XML com GZip.");
    }
    return base64_encode($gzipped);
}

/**
 * Descompacta Base64+GZip para XML
 */
function descompactarBase64Xml($base64) {
    $gzipped = base64_decode($base64);
    if ($gzipped === false) return $base64;
    $xml = @gzdecode($gzipped);
    return $xml !== false ? $xml : $base64;
}

/**
 * Monta XML da DPS (Declaração de Prestação de Serviços)
 * Layout NFS-e Nacional
 */
function montarXmlDps($config)
{
    $ns = 'http://www.sped.fazenda.gov.br/nfse';

    $competencia = !empty($config['competencia'])
        ? date('Y-m-d', strtotime($config['competencia']))
        : date('Y-m-d');

    $dataEmissao = date('Y-m-d\TH:i:sP');
    $cnpjLimpo = preg_replace('/\D/', '', $config['prestador_cnpj']);
    $tpInsc = (strlen($cnpjLimpo) == 14) ? '2' : '1';

    $idCorpo =
        str_pad($config['codigo_municipio_ibge'], 7, '0', STR_PAD_LEFT) .
        $tpInsc .
        str_pad($cnpjLimpo, 14, '0', STR_PAD_LEFT) .
        str_pad($config['dps_serie'], 5, '0', STR_PAD_LEFT) .
        str_pad($config['dps_numero'], 15, '0', STR_PAD_LEFT);

    $idDps = 'DPS' . $idCorpo;

    $xml  = '<?xml version="1.0" encoding="UTF-8"?>';
    $xml .= '<DPS xmlns="' . $ns . '" versao="1.01">';
    $xml .= '<infDPS Id="' . $idDps . '">';

    // ================= IDENTIFICAÇÃO =================

    $xml .= '<tpAmb>' . ($config['ambiente'] === 'producao' ? '1' : '2') . '</tpAmb>';
    $xml .= '<dhEmi>' . $dataEmissao . '</dhEmi>';
    $xml .= '<verAplic>1.0.0</verAplic>';
    $xml .= '<serie>' . $config['dps_serie'] . '</serie>';
    $xml .= '<nDPS>' . $config['dps_numero'] . '</nDPS>';
    $xml .= '<dCompet>' . $competencia . '</dCompet>';
    $xml .= '<tpEmit>1</tpEmit>';
    $xml .= '<cLocEmi>' . $config['codigo_municipio_ibge'] . '</cLocEmi>';

    // ================= PRESTADOR =================

    $xml .= '<prest>';

    $xml .= '<CNPJ>' . $cnpjLimpo . '</CNPJ>';

    if (!empty($config['prestador_telefone'])) {
        $xml .= '<fone>' . preg_replace('/\D/', '', $config['prestador_telefone']) . '</fone>';
    }

    if (!empty($config['prestador_email'])) {
        $xml .= '<email>' . $config['prestador_email'] . '</email>';
    }

    // No padrão Nacional, regTrib é um container para o detalhamento do regime
    $xml .= '<regTrib>';
    
    if ($config['regime_tributario'] == 1) { 
        // 1. Optante pelo Simples Nacional
        $xml .= '<opSimpNac>3</opSimpNac>'; 
        
        // 2. Regra de Apuração
        $regAp = ($config['prestador_mei'] ?? false) ? '2' : '1';
        $xml .= '<regApTribSN>' . $regAp . '</regApTribSN>';
        
        // 3. Regime Especial de Tributação (OBRIGATÓRIO para completar o Schema)
        // 0 - Nenhum
        $xml .= '<regEspTrib>0</regEspTrib>';
        
    } else {
        // Para não optantes (Lucro Presumido/Real)
        $xml .= '<opNaoSimpNac>1</opNaoSimpNac>';
        // Também exige o regEspTrib para não optantes no padrão 1.01
        $xml .= '<regEspTrib>0</regEspTrib>';
    }
    
    $xml .= '</regTrib>';

    $xml .= '</prest>';

    // ================= TOMADOR =================

    if (!empty($config['tomador_documento'])) {

        $xml .= '<toma>';

        $docLimpo = preg_replace('/\D/', '', $config['tomador_documento']);

        if (strlen($docLimpo) == 14) {
            $xml .= '<CNPJ>' . $docLimpo . '</CNPJ>';
        } else {
            $xml .= '<CPF>' . str_pad($docLimpo, 11, '0', STR_PAD_LEFT) . '</CPF>';
        }

        $xml .= '<xNome>' . htmlspecialchars($config['tomador_razao']) . '</xNome>';

        $xml .= '<end>';
        $xml .= '<endNac>';
        $xml .= '<cMun>' . trim($config['tomador_cod_mun']) . '</cMun>';
        $xml .= '<CEP>' . preg_replace('/\D/', '', $config['tomador_cep']) . '</CEP>';
        $xml .= '</endNac>'; // FECHA AQUI
        $xml .= '<xLgr>' . htmlspecialchars(trim($config['tomador_endereco'])) . '</xLgr>';
        $xml .= '<nro>' . htmlspecialchars(trim($config['tomador_numero'])) . '</nro>';
        $xml .= '<xBairro>' . htmlspecialchars(trim($config['tomador_bairro'])) . '</xBairro>';
        $xml .= '</end>';

        if (!empty($config['tomador_telefone'])) {
            $xml .= '<fone>' . preg_replace('/\D/', '', $config['tomador_telefone']) . '</fone>';
        }

        if (!empty($config['tomador_email'])) {
            $xml .= '<email>' . $config['tomador_email'] . '</email>';
        }

        $xml .= '</toma>';
    }

    // ================= SERVIÇO =================

    $xml .= '<serv>';
    
    $xml .= '<locPrest>';
    $xml .= '<cLocPrestacao>' . $config['codigo_municipio_ibge'] . '</cLocPrestacao>';
    $xml .= '</locPrest>';
    
    $xml .= '<cServ>';
    
    // 1. Tributação Nacional (Obrigatório)
    $xml .= '<cTribNac>' . trim($config['codigo_trib_nacional']) . '</cTribNac>';

    // 2. Tributação Municipal (Opcional - só envia se tiver valor)
    if (!empty($config['codigo_trib_municipal'])) {
        $xml .= '<cTribMun>' . trim($config['codigo_trib_municipal']) . '</cTribMun>';
    }

    // 3. Código Interno (Opcional - só envia se tiver valor)
    if (!empty($config['codigo_interno'])) {
        $xml .= '<cIntContrib>' . htmlspecialchars(trim($config['codigo_interno'])) . '</cIntContrib>';
    }

    // 4. Descrição do Serviço (Obrigatório)
    $xml .= '<xDescServ>' . htmlspecialchars(trim($config['discriminacao'])) . '</xDescServ>';

    // 5. NBS (Opcional - note o 'c' minúsculo)
    if (!empty($config['codigo_nbs'])) {
        $xml .= '<cNBS>' . trim($config['codigo_nbs']) . '</cNBS>';
    }

    $xml .= '</cServ>';

    $xml .= '</serv>';

    // ================= VALORES =================

    // ================= VALORES =================

    $xml .= '<valores>';
    $xml .= '<vServPrest>';
    $xml .= '<vServ>' . number_format((float)$config['valor_servicos'], 2, '.', '') . '</vServ>';
    $xml .= '</vServPrest>';

    $xml .= '<trib>';
    
    // 1. ISSQN (tribMun) - Já corrigido anteriormente
    $xml .= '<tribMun>';
    $xml .= '<tribISSQN>1</tribISSQN>';
    $xml .= '<tpRetISSQN>' . ($config['iss_retido'] ? '1' : '2') . '</tpRetISSQN>';
    if($config['iss_retido'] == '1'):
        $xml .= '<pAliq>' . number_format((float)$config['aliquota_iss'], 2, '.', '') . '</pAliq>';
    endif;
    $xml .= '</tribMun>';

    // 2. Totalizador de Tributos (Lei da Transparência)
    $xml .= '<totTrib>';
    
    if ($config['regime_tributario'] == 1) {
        // Para empresas do Simples Nacional (ME/EPP), informe o percentual aproximado
        // Se não tiver esse valor exato, você pode usar a alíquota do ISS ou um valor estimado (ex: 4.50)
        $aliqSimples = isset($config['aliquota_simples']) ? $config['aliquota_simples'] : $config['aliquota_iss'];
        $xml .= '<pTotTribSN>' . number_format((float)$aliqSimples, 2, '.', '') . '</pTotTribSN>';
    } else {
        // Para empresas de regime normal, o indicador de "não informar" (0) ainda é permitido
        $xml .= '<indTotTrib>0</indTotTrib>';
    }
    
    $xml .= '</totTrib>';

    $xml .= '</trib>';
    $xml .= '</valores>';

    $xml .= '</infDPS>';
    $xml .= '</DPS>';

    return $xml;
}

/**
 * Monta XML do Evento de Cancelamento
 * Layout NFS-e Nacional
 */
function montarXmlEventoCancelamento($config) {

    $ns = 'http://www.sped.fazenda.gov.br/nfse';
    
    $dataEvento = date('Y-m-d\TH:i:sP'); // gera -03:00 automático
    
    $chave = $config['cancelar_chave_acesso'];
    $cnpjAutor = preg_replace('/\D/', '', $config['prestador_cnpj']);
    
    // ID padrão novo: PRE + chave + 101101
    $id = 'PRE' . $chave . '101101';

    $xml  = '<?xml version="1.0" encoding="UTF-8"?>';
    $xml .= '<pedRegEvento versao="1.01" xmlns="' . $ns . '">';
    
    $xml .= '<infPedReg Id="' . $id . '">';
    $xml .= '<tpAmb>' . ($config['ambiente'] === 'producao' ? '1' : '2') . '</tpAmb>';
    $xml .= '<verAplic>1.0.0</verAplic>';
    $xml .= '<dhEvento>' . $dataEvento . '</dhEvento>';
    
    $xml .= '<CNPJAutor>' . $cnpjAutor . '</CNPJAutor>';
    $xml .= '<chNFSe>' . $chave . '</chNFSe>';

    $xml .= '<e101101>';
    $xml .= '<xDesc>Cancelamento de NFS-e</xDesc>';
    $xml .= '<cMotivo>1</cMotivo>';
    $xml .= '<xMotivo>' . htmlspecialchars($config['cancelar_motivo'], ENT_XML1) . '</xMotivo>';
    $xml .= '</e101101>';

    $xml .= '</infPedReg>';
    $xml .= '</pedRegEvento>';

    return $xml;
}

/**
 * Envia requisição REST via cURL com mTLS
 * API ADN NFS-e Nacional usa REST (JSON com XML GZip+Base64)
 */
function enviarApiRest($url, $method, $dados, $certFile, $keyFile, $headers = []) {
    
    $ch = curl_init();

    $defaultHeaders = [
        'Content-Type: application/json',
        'Accept: application/json',
    ];
    $allHeaders = array_merge($defaultHeaders, $headers);
    
    $curlOpts = [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $allHeaders,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_SSLCERT        => $certFile,
        CURLOPT_SSLKEY         => $keyFile,
        CURLOPT_TIMEOUT        => 60,
        CURLOPT_CONNECTTIMEOUT => 30,
    ];

    if ($method === 'POST') {
        $curlOpts[CURLOPT_POST] = true;
        if ($dados !== null) {
            $body = is_string($dados) ? $dados : json_encode($dados, JSON_UNESCAPED_UNICODE);
            $curlOpts[CURLOPT_POSTFIELDS] = $body;
            $allHeaders[] = 'Content-Length: ' . strlen($body);
            $curlOpts[CURLOPT_HTTPHEADER] = $allHeaders;
        }
    } elseif ($method === 'GET') {
        $curlOpts[CURLOPT_HTTPGET] = true;
    } elseif ($method === 'HEAD') {
        $curlOpts[CURLOPT_NOBODY] = true;
    }

    curl_setopt_array($ch, $curlOpts);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error    = curl_error($ch);
    $errno    = curl_errno($ch);
    
    $info    = curl_getinfo($ch);
    
    curl_close($ch);
    
    return [
        'response'  => $response,
        'http_code' => $httpCode,
        'error'     => $error,
        'errno'     => $errno,
        'request'   => isset($body) ? $body : '',
    ];
}

/**
 * Formata XML para exibição
 */
function formatarXml($xml) {
    if (empty($xml)) return '';
    $doc = new DOMDocument('1.0', 'UTF-8');
    $doc->preserveWhiteSpace = false;
    $doc->formatOutput = true;
    @$doc->loadXML($xml);
    return $doc->saveXML();
}

function formatarResposta($conteudo) {

    if (empty($conteudo)) return '';

    $conteudo = trim($conteudo);

    // Se for JSON
    if ($conteudo[0] === '{' || $conteudo[0] === '[') {
        $json = json_decode($conteudo, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return json_encode($json, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        }
        return $conteudo; // JSON inválido
    }

    // Se for XML
    if ($conteudo[0] === '<') {
        $doc = new DOMDocument('1.0', 'UTF-8');
        $doc->preserveWhiteSpace = false;
        $doc->formatOutput = true;

        if (@$doc->loadXML($conteudo)) {
            return $doc->saveXML();
        }
    }

    // Se não for nenhum dos dois
    return $conteudo;
}

/**
 * Formata JSON para exibição
 */
function formatarJson($json) {
    if (empty($json)) return '';
    $decoded = json_decode($json);
    if ($decoded === null) return $json;
    return json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
}

/**
 * Extrai conteúdo da resposta SOAP
 */
function extrairResposta($resposta) {

    if (empty($resposta)) return '';

    // Se começar com { é JSON
    if (trim($resposta)[0] === '{') {
        return json_decode($resposta, true);
    }

    // Caso seja XML / SOAP
    $doc = new DOMDocument();
    @$doc->loadXML($resposta);

    $outputs = $doc->getElementsByTagName('outputXML');
    if ($outputs->length > 0) {
        return $outputs->item(0)->nodeValue;
    }

    return $resposta;
}


/**
 * Analisa erros da resposta da API
 */
function analisarErrosResposta($responseBody) {

    $erros = [];
    if (empty($responseBody)) return $erros;

    $data = json_decode($responseBody, true);
    if (!$data) return $erros;

    // Portal Nacional (padrão oficial)
    if (isset($data['erros']) && is_array($data['erros'])) {
        foreach ($data['erros'] as $e) {
            $erros[] = [
                'codigo'   => $e['Codigo'] ?? $e['codigo'] ?? '',
                'mensagem' => $e['Descricao'] ?? $e['descricao'] ?? '',
                'correcao' => $e['Correcao'] ?? $e['correcao'] ?? '',
            ];
        }
    }

    // Caso venha erro único
    if (isset($data['Codigo']) || isset($data['codigo'])) {
        $erros[] = [
            'codigo'   => $data['Codigo'] ?? $data['codigo'] ?? '',
            'mensagem' => $data['Descricao'] ?? $data['descricao'] ?? '',
            'correcao' => $data['Correcao'] ?? '',
        ];
    }

    return $erros;
}

/**
 * Extrai dados da NFS-e da resposta
 */
function extrairDadosNfse($responseBody) {

    if (empty($responseBody)) return null;

    $data = json_decode($responseBody, true);
    if (!$data) return null;

    $dados = [];

    // Sucesso Portal Nacional
    if (isset($data['chaveAcesso'])) {
        $dados['Chave de Acesso'] = $data['chaveAcesso'];
    }

    if (isset($data['numeroNfse'])) {
        $dados['Número NFS-e'] = $data['numeroNfse'];
    }

    if (isset($data['idDps'])) {
        $dados['Id DPS'] = $data['idDps'];
    }

    if (isset($data['dataHoraProcessamento'])) {
        $dados['Data Processamento'] = $data['dataHoraProcessamento'];
    }

    // XML vem como GZIP + Base64
    if (isset($data['nfseXmlGZipB64'])) {

        $xmlCompactado = base64_decode($data['nfseXmlGZipB64']);
        $xmlNfse = gzdecode($xmlCompactado);

        if ($xmlNfse) {

            $dados['xmlCompleto'] = $xmlNfse;

            $doc = new DOMDocument();
            @$doc->loadXML($xmlNfse);

            $tags = ['nNFSe','cLocEmi','dhEmi','vServ','vLiq','vISS'];

            foreach ($tags as $tag) {
                $el = $doc->getElementsByTagName($tag)->item(0);
                if ($el) {
                    $dados[$tag] = $el->nodeValue;
                }
            }
        }
    }

    return !empty($dados) ? $dados : null;
}

// ==== PROCESSAMENTO ====

$resultado = null;
$erro = null;
$xmlEnviado = '';
$xmlResposta = '';
$jsonEnviado = '';
$respostaRaw = '';
$respostaFormatada = '';
$errosNfse = [];
$dadosNfse = null;
$operacaoExecutada = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Atualizar config com dados do formulário
        foreach ($_POST as $key => $value) {
            if (array_key_exists($key, $config) && !in_array($key, ['emitir', 'consultar', 'consultar_dps', 'cancelar'])) {
                if ($value === 'true') $config[$key] = true;
                elseif ($value === 'false') $config[$key] = false;
                else $config[$key] = trim($value);
            }
        }
        // Checkboxes
        $config['iss_retido'] = $_POST['iss_retido'];
        $config['optante_simples'] = $_POST['optante_simples'];

        // Extrair certificado
        $cert = extrairCertificado($config['certificado_pfx'], $config['certificado_senha']);

        // Determinar URL base
        $baseUrl = ($config['ambiente'] === 'producao') ? $config['url_producao'] : $config['url_homologacao'];

        // ---- GERAR NFSe (Enviar DPS) ----
        if (isset($_POST['emitir'])) {
            $operacaoExecutada = 'Enviar DPS (Gerar NFS-e)';

            // 1. Montar XML da DPS
            $xmlDps = montarXmlDps($config);

            // 2. Assinar XML
            $xmlAssinado = assinarXml($xmlDps, $cert['cert'], $cert['pkey'], 'infDPS');
            
            // --- LIMPEZA DE SEGURANÇA ---
            $xmlParaEnvio = trim($xmlAssinado);
            // Remove o BOM se existir
            $xmlParaEnvio = str_replace("\xEF\xBB\xBF", '', $xmlParaEnvio); 

            $xmlEnviado = $xmlParaEnvio;
            
            // 3. Compactar (GZip) e codificar (Base64)
            $dpsBase64 = compactarXmlBase64($xmlParaEnvio);

            // 4. Montar JSON para envio
            $payload = json_encode([
                'dpsXmlGZipB64' => $dpsBase64,
            ], JSON_UNESCAPED_UNICODE);
            $jsonEnviado = $payload;

            // 5. Enviar via POST para API ADN
            $url = $baseUrl . '/nfse';

            $result = enviarApiRest($url, 'POST', $payload, $cert['certFile'], $cert['keyFile']);
        }
        // ---- CONSULTAR NFS-e POR CHAVE DE ACESSO ----
        elseif (isset($_POST['consultar'])) {
            $operacaoExecutada = 'Consultar NFS-e por Chave de Acesso';
            $chave = $config['consultar_chave_acesso'];
            if (empty($chave)) {
                throw new Exception("Informe a Chave de Acesso para consulta.");
            }
            $url = $baseUrl . '/nfse/' . urlencode($chave);
            $result = enviarApiRest($url, 'GET', null, $cert['certFile'], $cert['keyFile']);
        }
        // ---- CONSULTAR DPS (verificar se virou NFS-e) ----
        elseif (isset($_POST['consultar_dps'])) {
            $operacaoExecutada = 'Consultar DPS por ID';
            $idDps = $config['consultar_id_dps'];
            if (empty($idDps)) {
                throw new Exception("Informe o ID da DPS para consulta.");
            }
            $url = $baseUrl . '/dps/' . urlencode($idDps);
            $result = enviarApiRest($url, 'GET', null, $cert['certFile'], $cert['keyFile']);
        }
        // ---- CANCELAR NFSe (Evento) ----
        elseif (isset($_POST['cancelar'])) {
            $operacaoExecutada = 'Cancelar NFS-e (Evento)';
            $chave = $config['cancelar_chave_acesso'];
            if (empty($chave)) {
                throw new Exception("Informe a Chave de Acesso da NFS-e para cancelamento.");
            }

            // 1. Montar XML do evento
            $xmlEvento = montarXmlEventoCancelamento($config);

            // 2. Assinar XML
            $xmlAssinado = assinarXml($xmlEvento, $cert['cert'], $cert['pkey'], 'infPedReg');
            
//            die($xmlAssinado);
            // 3. Compactar e codificar
            $eventoBase64 = compactarXmlBase64($xmlAssinado);

            // 4. Montar JSON
            $payload = json_encode([
                'pedidoRegistroEventoXmlGZipB64' => $eventoBase64,
            ], JSON_UNESCAPED_UNICODE);
            $jsonEnviado = $payload;

            // 5. Enviar via POST
            $url = $baseUrl . '/nfse/' . urlencode($chave) . '/eventos';
            
            $result = enviarApiRest($url, 'POST', $payload, $cert['certFile'], $cert['keyFile']);
        }

        // Limpar temporários
        @unlink($cert['certFile']);
        @unlink($cert['keyFile']);

        // Processar resposta
        if ($result['errno'] !== 0) {
            $erro = "Erro cURL ({$result['errno']}): {$result['error']}";
        } else {
            $respostaRaw = $result['response'];
            $respostaFormatada = formatarJson($respostaRaw);
            
            $xmlResposta = $result['response'];
            $xmlRespostaFormatado = formatarResposta($xmlResposta);
            
            $errosNfse = analisarErrosResposta($respostaRaw);
            $dadosNfse = extrairDadosNfse($respostaRaw);

            
            if ($result['http_code'] < 200 || $result['http_code'] >= 300) {
                $erro = "HTTP {$result['http_code']}";
            }

            $resultado = ['http_code' => $result['http_code'], 'conteudo' => $respostaRaw];
        }
    } catch (Exception $e) {
        $erro = $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>NFSe Nacional - Rio de Janeiro/RJ</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f0f2f5; padding: 20px; }
        .container { max-width: 960px; margin: 0 auto; }
        h1 { color: #1a5276; margin-bottom: 5px; font-size: 22px; }
        .subtitle { color: #666; margin-bottom: 20px; font-size: 13px; }
        .card { background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .card h2 { color: #2c3e50; font-size: 16px; margin-bottom: 12px; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; }
        .field { margin-bottom: 8px; }
        .field label { display: block; font-size: 12px; color: #555; margin-bottom: 2px; font-weight: 600; }
        .field input, .field select, .field textarea { width: 100%; padding: 7px 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px; }
        .field textarea { height: 60px; resize: vertical; }
        .field input:focus, .field select:focus { border-color: #3498db; outline: none; }
        .field-check { display: flex; align-items: center; gap: 6px; margin-bottom: 8px; }
        .field-check input[type="checkbox"] { width: auto; }
        .field-check label { font-size: 12px; color: #555; font-weight: 600; margin: 0; }
        .btn { color: #fff; border: none; padding: 12px 30px; border-radius: 5px; font-size: 14px; cursor: pointer; font-weight: bold; margin: 5px; }
        .btn-gerar { background: #27ae60; } .btn-gerar:hover { background: #219a52; }
        .btn-consultar { background: #2980b9; } .btn-consultar:hover { background: #2471a3; }
        .btn-cancelar { background: #e74c3c; } .btn-cancelar:hover { background: #c0392b; }
        .alert { padding: 12px 15px; border-radius: 5px; margin-bottom: 15px; font-size: 13px; }
        .alert-error { background: #fce4e4; color: #c0392b; border: 1px solid #e74c3c; }
        .alert-success { background: #d5f5e3; color: #1e8449; border: 1px solid #27ae60; }
        .alert-warning { background: #fef9e7; color: #9a7d0a; border: 1px solid #f1c40f; }
        .alert-info { background: #d6eaf8; color: #1a5276; border: 1px solid #3498db; }
        .xml-box { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 400px; overflow-y: auto; }
        .toggle-btn { background: #3498db; color: #fff; border: none; padding: 5px 12px; border-radius: 3px; cursor: pointer; font-size: 12px; margin-bottom: 8px; }
        .full-width { grid-column: 1 / -1; }
        .env-badge { display: inline-block; padding: 3px 10px; border-radius: 3px; font-size: 11px; font-weight: bold; }
        .env-prod { background: #e74c3c; color: #fff; }
        .env-hom { background: #f39c12; color: #fff; }
        .erro-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }
        .erro-table th { background: #e74c3c; color: #fff; padding: 8px; text-align: left; }
        .erro-table td { padding: 8px; border-bottom: 1px solid #eee; vertical-align: top; }
        .nfse-dados { background: #d5f5e3; border: 2px solid #27ae60; border-radius: 8px; padding: 15px; margin-bottom: 15px; }
        .nfse-dados h3 { color: #1e8449; margin-bottom: 10px; }
        .nfse-dados table { width: 100%; font-size: 14px; }
        .nfse-dados td { padding: 5px 10px; }
        .nfse-dados td:first-child { font-weight: bold; color: #555; width: 200px; }
        .tabs { display: flex; gap: 0; margin-bottom: 0; }
        .tab { padding: 10px 20px; background: #ecf0f1; border: 1px solid #bdc3c7; border-bottom: none; cursor: pointer; font-size: 13px; font-weight: 600; border-radius: 5px 5px 0 0; }
        .tab.active { background: #fff; border-bottom: 1px solid #fff; color: #2980b9; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
    <script>
    function showTab(tabName) {
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
        document.getElementById('tab-' + tabName).classList.add('active');
        document.querySelector('[onclick="showTab(\'' + tabName + '\')"]').classList.add('active');
    }
    function toggleEl(id) {
        var el = document.getElementById(id);
        el.style.display = el.style.display === 'none' ? 'block' : 'none';
    }
    </script>
</head>
<body>
<div class="container">
    <h1>🧾 NFSe Nacional - Rio de Janeiro/RJ</h1>
    <p class="subtitle">
        Padrão Nacional NFSe (ADN) - IBGE: 3304557 |
        <span class="env-badge <?=$config['ambiente'] === 'producao' ? 'env-prod' : 'env-hom' ?>">
            <?=strtoupper($config['ambiente']) ?>
        </span>
        <?php if ($operacaoExecutada): ?>
        | Operação: <strong><?=$operacaoExecutada ?></strong>
        <?php endif; ?>
    </p>

    <?php if ($erro): ?>
        <div class="alert alert-error">⚠️ <strong>Erro:</strong> <?=htmlspecialchars($erro) ?></div>
    <?php endif; ?>

    <?php if (empty($errosNfse) AND $dadosNfse): ?>
        <div class="nfse-dados">
            <h3>✅ NFSe Processada com Sucesso!</h3>
            <table>
                <?php foreach ($dadosNfse as $campo => $valor): ?>
                <?php if (!empty($valor)): ?>
                <tr><td><?=htmlspecialchars($campo) ?></td><td><?=htmlspecialchars($valor) ?></td></tr>
                <?php endif; ?>
                <?php endforeach; ?>
            </table>
        </div>
    <?php elseif ($resultado && empty($errosNfse) && !$erro): ?>
        <div class="alert alert-success">✅ Requisição processada com sucesso (HTTP <?=$resultado['http_code'] ?>)</div>
    <?php elseif ($resultado && !empty($errosNfse)): ?>
        <div class="alert alert-warning">⚠️ Retornou <?=count($errosNfse) ?> erro(s)</div>
    <?php endif; ?>

    <?php if (!empty($errosNfse)): ?>
    <div class="card">
        <h2>❌ Erros Retornados</h2>
        <table class="erro-table">
            <thead><tr><th style="width:70px;">Código</th><th>Mensagem</th><th>Correção</th></tr></thead>
            <tbody>
            <?php foreach ($errosNfse as $e): ?>
            <tr>
                <td style="font-weight:bold;color:#c0392b;"><?=htmlspecialchars($e['codigo']) ?></td>
                <td><?=htmlspecialchars($e['mensagem']) ?></td>
                <td><?=htmlspecialchars($e['correcao']) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

    <form method="POST">
        <!-- AMBIENTE E CERTIFICADO -->
        <div class="card">
            <h2>🔐 Ambiente e Certificado</h2>
            <div class="grid">
                <div class="field">
                    <label>Ambiente</label>
                    <select name="ambiente">
                    <option value="homologacao" <?=$config['ambiente'] === 'homologacao' ? 'selected' : '' ?>>🟡 Homologação (Produção Restrita)</option>
                    <option value="producao" <?=$config['ambiente'] === 'producao' ? 'selected' : '' ?>>🔴 Produção</option>
                    </select>
                </div>
                <div class="field">
                    <label>Arquivo Certificado (.pfx)</label>
                    <input type="text" name="certificado_pfx" value="<?=htmlspecialchars($config['certificado_pfx']) ?>">
                </div>
                <div class="field full-width">
                    <label>Senha do Certificado</label>
                    <input type="password" name="certificado_senha" value="<?=htmlspecialchars($config['certificado_senha']) ?>">
                </div>
            </div>
        </div>

        <!-- PRESTADOR -->
        <div class="card">
            <h2>🏢 Prestador</h2>
            <div class="grid">
                <div class="field">
                    <label>CNPJ (14 dígitos)</label>
                    <input type="text" name="prestador_cnpj" value="<?=htmlspecialchars($config['prestador_cnpj']) ?>" maxlength="14">
                </div>
                <div class="field">
                    <label>Inscrição Municipal</label>
                    <input type="text" name="prestador_im" value="<?=htmlspecialchars($config['prestador_im']) ?>">
                </div>
                <div class="field">
                    <label>Razão Social</label>
                    <input type="text" name="prestador_razao" value="<?=htmlspecialchars($config['prestador_razao']) ?>">
                </div>
                <div class="field">
                    <label>Nome Fantasia</label>
                    <input type="text" name="prestador_nome_fantasia" value="<?=htmlspecialchars($config['prestador_nome_fantasia']) ?>">
                </div>
            </div>
        </div>

        <!-- ABAS -->
        <div class="tabs">
            <div class="tab active" onclick="showTab('gerar')">🚀 Gerar NFSe</div>
            <div class="tab" onclick="showTab('consultar')">🔍 Consultar</div>
            <div class="tab" onclick="showTab('cancelar')">❌ Cancelar NFSe</div>
        </div>

        <!-- ABA GERAR -->
        <div id="tab-gerar" class="tab-content active">
            <div class="card" style="border-radius: 0 8px 8px 8px;">
                <h2>📄 DPS (Declaração de Prestação de Serviços)</h2>
                <div class="grid-3">
                    <div class="field"><label>Série</label><input type="text" name="dps_serie" value="<?=htmlspecialchars($config['dps_serie']) ?>" maxlength="5"></div>
                    <div class="field"><label>Número</label><input type="text" name="dps_numero" value="<?=htmlspecialchars($config['dps_numero']) ?>"></div>
                    <div class="field"><label>Competência (AAAA-MM)</label><input type="text" name="competencia" value="<?=htmlspecialchars($config['competencia']) ?>" placeholder="<?= date('Y-m') ?>"></div>
                </div>

                <h2 style="margin-top:15px;">🔧 Serviço</h2>
                <div class="grid">
                    <div class="field"><label>Valor (R$)</label><input type="text" name="valor_servicos" value="<?=htmlspecialchars($config['valor_servicos']) ?>"></div>
                    <div class="field"><label>Alíquota ISS (%)</label><input type="text" name="aliquota_iss" value="<?=htmlspecialchars($config['aliquota_iss']) ?>"></div>
                    <div class="field"><label>Cód. Tributação Nacional (iissdd)</label><input type="text" name="codigo_trib_nacional" value="<?=htmlspecialchars($config['codigo_trib_nacional']) ?>" maxlength="6" placeholder="Ex: 010101"></div>
                    <div class="field"><label>Cód. Complementar Municipal (xxx)</label><input type="text" name="codigo_trib_municipal" value="<?=htmlspecialchars($config['codigo_trib_municipal']) ?>" maxlength="3" placeholder="Ex: 001"></div>
                    <div class="field"><label>NBS (opcional)</label><input type="text" name="codigo_nbs" value="<?=htmlspecialchars($config['codigo_nbs']) ?>"></div>
                    <div class="field"><label>Cód. Município IBGE</label><input type="text" name="codigo_municipio_ibge" value="<?=htmlspecialchars($config['codigo_municipio_ibge']) ?>"></div>
                    <div class="field"><label>Valor Deduções (R$)</label><input type="text" name="valor_deducoes" value="<?=htmlspecialchars($config['valor_deducoes']) ?>"></div>
                    <div class="field"><label>Desc. Incondicionado (R$)</label><input type="text" name="valor_desconto_incond" value="<?=htmlspecialchars($config['valor_desconto_incond']) ?>"></div>
                    <div class="field">
                        <label>Regime Especial</label>
                        <select name="regime_especial">
                        <option value="0" <?=$config['regime_especial'] == '0' ? 'selected' : '' ?>>0 - Nenhum</option>
                        <option value="1" <?=$config['regime_especial'] == '1' ? 'selected' : '' ?>>1 - Microempresa</option>
                        <option value="2" <?=$config['regime_especial'] == '2' ? 'selected' : '' ?>>2 - Estimativa</option>
                        <option value="3" <?=$config['regime_especial'] == '3' ? 'selected' : '' ?>>3 - Soc. Profissionais</option>
                        <option value="4" <?=$config['regime_especial'] == '4' ? 'selected' : '' ?>>4 - Cooperativa</option>
                        <option value="5" <?=$config['regime_especial'] == '5' ? 'selected' : '' ?>>5 - MEI</option>
                        <option value="6" <?=$config['regime_especial'] == '6' ? 'selected' : '' ?>>6 - ME/EPP</option>
                        </select>
                    </div>
                    
                    <div class="field"><label>ISS Retido</label><select name="iss_retido"><option value="2" <?= $config['iss_retido'] == '2' ? 'selected' : '' ?>>2 - Não</option><option value="1" <?= $config['iss_retido'] == '1' ? 'selected' : '' ?>>1 - Sim</option></select></div>
                    <div class="field"><label>Simples Nacional</label><select name="optante_simples"><option value="2" <?= $config['optante_simples'] == '2' ? 'selected' : '' ?>>2 - Não</option><option value="1" <?= $config['optante_simples'] == '1' ? 'selected' : '' ?>>1 - Sim</option></select></div>
                    
                    
                    <div class="field full-width"><label>Discriminação do Serviço</label><textarea name="discriminacao"><?=htmlspecialchars($config['discriminacao']) ?></textarea></div>
                </div>

                <h2 style="margin-top:15px;">👤 Tomador</h2>
                <div class="grid">
                    <div class="field"><label>CNPJ/CPF</label><input type="text" name="tomador_documento" value="<?=htmlspecialchars($config['tomador_documento']) ?>"></div>
                    <div class="field"><label>Razão Social / Nome</label><input type="text" name="tomador_razao" value="<?=htmlspecialchars($config['tomador_razao']) ?>"></div>
                    <div class="field"><label>Endereço (Logradouro)</label><input type="text" name="tomador_endereco" value="<?=htmlspecialchars($config['tomador_endereco']) ?>"></div>
                    <div class="field"><label>Número</label><input type="text" name="tomador_numero" value="<?=htmlspecialchars($config['tomador_numero']) ?>"></div>
                    <div class="field"><label>Complemento</label><input type="text" name="tomador_complemento" value="<?=htmlspecialchars($config['tomador_complemento']) ?>"></div>
                    <div class="field"><label>Bairro</label><input type="text" name="tomador_bairro" value="<?=htmlspecialchars($config['tomador_bairro']) ?>"></div>
                    <div class="field"><label>CEP</label><input type="text" name="tomador_cep" value="<?=htmlspecialchars($config['tomador_cep']) ?>" maxlength="8"></div>
                    <div class="field"><label>UF</label><input type="text" name="tomador_uf" value="<?=htmlspecialchars($config['tomador_uf']) ?>" maxlength="2"></div>
                    <div class="field"><label>Cód. Município IBGE</label><input type="text" name="tomador_cod_mun" value="<?=htmlspecialchars($config['tomador_cod_mun']) ?>"></div>
                    <div class="field"><label>Email</label><input type="text" name="tomador_email" value="<?=htmlspecialchars($config['tomador_email']) ?>"></div>
                    <div class="field"><label>Telefone</label><input type="text" name="tomador_telefone" value="<?=htmlspecialchars($config['tomador_telefone']) ?>"></div>
                </div>

                <div style="text-align:center;margin-top:15px;">
                    <button type="submit" name="emitir" value="1" class="btn btn-gerar" onclick="return confirm('Confirma emissão no ambiente de <?=$config['ambiente'] ?>?');">🚀 EMITIR NFSe</button>
                </div>
            </div>
        </div>

        <!-- ABA CONSULTAR -->
        <div id="tab-consultar" class="tab-content">
            <div class="card" style="border-radius: 0 8px 8px 8px;">
                <h2>🔍 Consultar NFS-e por Chave de Acesso</h2>
                <div class="field">
                    <label>Chave de Acesso (50 caracteres)</label>
                    <input type="text" name="consultar_chave_acesso" value="<?=htmlspecialchars($config['consultar_chave_acesso']) ?>" maxlength="50" placeholder="Chave de acesso da NFS-e">
                </div>
                <div style="text-align:center;margin-top:15px;">
                    <button type="submit" name="consultar" value="1" class="btn btn-consultar">🔍 CONSULTAR NFS-e</button>
                </div>

                <hr style="margin: 20px 0; border: none; border-top: 1px solid #eee;">

                <h2>🔍 Consultar DPS por ID</h2>
                <div class="field">
                    <label>ID da DPS</label>
                    <input type="text" name="consultar_id_dps" value="<?=htmlspecialchars($config['consultar_id_dps']) ?>" placeholder="ID da DPS enviada">
                </div>
                <div style="text-align:center;margin-top:15px;">
                    <button type="submit" name="consultar_dps" value="1" class="btn btn-consultar">🔍 CONSULTAR DPS</button>
                </div>
            </div>
        </div>

        <!-- ABA CANCELAR -->
        <div id="tab-cancelar" class="tab-content">
            <div class="card" style="border-radius: 0 8px 8px 8px;">
                <h2>❌ Cancelar NFS-e (Evento)</h2>
                <div class="grid">
                    <div class="field">
                        <label>Chave de Acesso da NFS-e</label>
                        <input type="text" name="cancelar_chave_acesso" value="<?=htmlspecialchars($config['cancelar_chave_acesso']) ?>" maxlength="50">
                    </div>
                    <div class="field">
                        <label>Motivo do Cancelamento</label>
                        <input type="text" name="cancelar_motivo" value="<?=htmlspecialchars($config['cancelar_motivo']) ?>">
                    </div>
                </div>
                <div style="text-align:center;margin-top:15px;">
                    <button type="submit" name="cancelar" value="1" class="btn btn-cancelar" onclick="return confirm('⚠️ ATENÇÃO: Confirma o CANCELAMENTO da NFSe?');">❌ CANCELAR NFSe</button>
                </div>
            </div>
        </div>
    </form>

    <!-- RESULTADOS -->
    <?php if ($jsonEnviado): ?>
    <div class="card">
        <h2>📨 JSON Enviado (Request Body)</h2>
        <button class="toggle-btn" onclick="toggleEl('jsonEnv')">Mostrar/Ocultar</button>
        <div id="jsonEnv" class="xml-box" style="display:none;"><?=htmlspecialchars(formatarJson($jsonEnviado)) ?></div>
    </div>
    <?php endif; ?>

    <?php if ($xmlEnviado): ?>
    <div class="card">
        <h2>📤 XML Assinado (DPS/Evento)</h2>
        <button class="toggle-btn" onclick="toggleEl('xmlEnv')">Mostrar/Ocultar</button>
        <div id="xmlEnv" class="xml-box" style="display:block;"><?=htmlspecialchars(formatarXml($xmlEnviado)) ?></div>
    </div>
    <?php endif; ?>

    <?php if ($xmlResposta): ?>
    <div class="card">
        <h2>📥 Resposta SOAP Completa</h2>
        <button class="toggle-btn" onclick="toggleEl('xmlResp')">Mostrar/Ocultar</button>
        <div id="xmlResp" class="xml-box" style="display:none;"><?= htmlspecialchars($xmlResposta) ?></div>
    </div>
    <div class="card">
        <h2>📋 Conteúdo Extraído</h2>
        <div class="xml-box"><?= htmlspecialchars($xmlRespostaFormatado ?: 'Sem conteúdo') ?></div>
    </div>
    <?php endif; ?>

    
     <!-- REFERÊNCIA -->
    <div class="card" style="background: #eaf2f8;">
        <h2>ℹ️ Referência</h2>
        <div style="font-size: 12px; color: #555; line-height: 1.8;">
            <strong>Produção:</strong> <code>https://sefin.nfse.gov.br/SefinNacional</code><br>
            <strong>Homologação:</strong> <code>https://sefin.producaorestrita.nfse.gov.br/SefinNacional</code><br>
            <strong>Namespace Request:</strong> <code>http://nfse.abrasf.org.br</code><br>
            <strong>Namespace Dados:</strong> <code>http://www.abrasf.org.br/nfse.xsd</code><br>
            <strong>Versão:</strong> 2.02 | <strong>IBGE:</strong>3304557<br><br>
            <strong>Formato SOAP correto (WebISS .asmx):</strong><br>
        </div>
    </div>