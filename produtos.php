<?php
// Carregar o autoloader do Composer
require_once 'vendor/autoload.php';

// Carregar as variáveis do arquivo .env
use Dotenv\Dotenv;
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Recuperando as variáveis do .env
$clientId = $_ENV['CLIENT_ID'];
$secretKey = $_ENV['SECRET_KEY'];
$accessToken = $_ENV['ACCESS_TOKEN'];

// URL da API do Bling
$blingApiUrl = "https://www.bling.com.br/Api/v3/produtos";

// Função para obter os produtos
function getProducts($blingApiUrl, $accessToken)
{
    $ch = curl_init();

    // Configurando a requisição cURL
    curl_setopt($ch, CURLOPT_URL, $blingApiUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer $accessToken"
    ]);

    // Executando a requisição e fechando a conexão
    $response = curl_exec($ch);
    curl_close($ch);

    // Verificando se ocorreu algum erro
    if (!$response) {
        die("Erro na requisição: " . curl_error($ch));
    }

    return json_decode($response, true);
}

// Obtendo os produtos
$products = getProducts($blingApiUrl, $accessToken);

// Exibindo os produtos em formato JSON
header('Content-Type: application/json');
echo json_encode($products);
?>
