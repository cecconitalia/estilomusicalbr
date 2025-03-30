let clientId = '8cc5f15fe336bc0f8ec827e16a6a05d663e3c134';
let secretKey = 'b1deb811eb93883d3504175430756f0be55082874e25c541a357532ab757';
let code = '22a876822934bd67c24371db89bdf7e709775245';

function getToken()
{
  let credentials = Utilities.base64Encode(clientId+':'+secretKey);
  let options = {
    'method':'POST',
    'payload':{
      'grant_type':'authorization_code',
      'code': code
    },
    'headers':{
      'Content-Type':'application/x-www-form-urlencoded',
      'Authorization': `Basic ${credentials}`
    }
  }
    let reqs = UrlFetchApp.fetch(`https://www.bling.com.br/Api/v3/oauth/token`,options);
    let ress = JSON.parse(reqs.getContentText());
    console.log(ress);
}