
async function sha256(msgBuffer) 
{
    var hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    var hashArray = Array.from(new Uint8Array(hashBuffer));
    // клоунада из-за .encrypt(text: string) в jsbn
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
/*
async function sign(hash, key) 
{
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(key);
    return encrypt.encrypt(hash);
}*/
async function encryptRSA(data, key) 
{
    var encrypt = new JSEncrypt();
	encrypt.setPublicKey(key);
	console.log('data='+data);
    var r = encrypt.encrypt(data);
	if (r === false)
		sc1('e');
	console.log('r='+r);
	return r;
}
async function decryptRSA(data, key) 
{
    var encrypt = new JSEncrypt();
	encrypt.setPrivateKey(key);
    var r = encrypt.decrypt(data);
	if (r === false)
		sc1('e');
	return r;
}

async function sign(data, key) 
{
    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey(key);
	console.log('sdata[0]=' + data[0]);
    return encrypt.sign(data, CryptoJS.SHA256, 'sha256');
}

async function verify(message, signature, key) 
{
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(key);
	console.log('message[0]=' + message[0]);
    return encrypt.verify(message, signature, CryptoJS.SHA256);
}

function arrayBufferToHex(buffer) 
{
    var byteArray = new Uint8Array(buffer);
    let hexString = '';

    for (let i = 0; i < byteArray.length; i++) 
	{
        var hex = byteArray[i].toString(16).padStart(2, '0');
        hexString += hex;
    }

    return hexString;
}
function hexToArrayBuffer(hex) 
{
    hex = hex.replace(/\s+/g, '').toUpperCase();
    
    var buffer = new ArrayBuffer(hex.length / 2);
    var byteArray = new Uint8Array(buffer);

    for (let i = 0; i < hex.length; i += 2)
        byteArray[i / 2] = parseInt(hex.substr(i, 2), 16);

    return buffer;
}


function hexToString(hex) 
{
    let str = '';
    for (let i = 0; i < hex.length; i += 2) 
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

function stringToHex(str) 
{
    let hex = '';
    for (let i = 0; i < str.length; i++)
        hex += str.charCodeAt(i).toString(16).padStart(2, '0');
    return hex;
}

var JsonFormatter = {
  stringify: function(cipherParams) {
    // create json object with ciphertext
    var jsonObj = { ct: cipherParams.ciphertext.toString(CryptoJS.enc.Base64) };
    // optionally add iv or salt
    if (cipherParams.iv) {
      jsonObj.iv = cipherParams.iv.toString();
    }
    if (cipherParams.salt) {
      jsonObj.s = cipherParams.salt.toString();
    }
    // stringify json object
    return JSON.stringify(jsonObj);
  },
  parse: function(jsonStr) {
    // parse json string
    var jsonObj = JSON.parse(jsonStr);
    // extract ciphertext from json object, and create cipher params object
    var cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Base64.parse(jsonObj.ct)
    });
    // optionally extract iv or salt
    if (jsonObj.iv) {
      cipherParams.iv = CryptoJS.enc.Hex.parse(jsonObj.iv);
    }
    if (jsonObj.s) {
      cipherParams.salt = CryptoJS.enc.Hex.parse(jsonObj.s);
    }
    return cipherParams;
  }
};

function sc1(text, dur)
{
    Toastify({
       text: text,
       duration: typeof dur == 'undefined' ? 1000 : (dur * 1000)
    }).showToast();
}

function download_file(filename, data) 
{
    var blob = new Blob([data]);//, { type: 'text/plain' });

    var url = URL.createObjectURL(blob);

    var a = document.createElement('a');
    a.href = url;
    a.download = filename; 
    document.body.appendChild(a);

    a.click();

    document.body.removeChild(a);

    URL.revokeObjectURL(url);
}

function generate_random_key_and_iv(size) 
{
    const key = crypto.getRandomValues(new Uint8Array(size));
    const iv = crypto.getRandomValues(new Uint8Array(size));
    return {
        key: CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.create(key)),
        iv: CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.create(iv))
    };
}

var SC1_SIGN_HASH = undefined;
var SC1_ENCRYPTED = undefined;

function sc1load()
{
	$(document).ready(() => {
	    $('#formContainer').fadeIn();
	    $('#sc1Form').fadeIn();
		
		$('#sc1SignFormButton').click(async () => 
		{
			var fileInput = $('#sc1File')[0];
			var keyInput = $('#sc1PrivKey')[0];

			if (fileInput.files.length === 0 || keyInput.files.length === 0) 
			{
				sc1("Не указаны файлы");
			    return;
			}
			
			sc1("Чтение...");
			var file = fileInput.files[0];
			var keyFile = keyInput.files[0];

			var data = arrayBufferToHex/*new TextDecoder().decode*/(await file.arrayBuffer());
			var keyArrayBuffer = new TextDecoder().decode(await keyFile.arrayBuffer());

			sc1("Подпись...");
			var signData = SC1_SIGN_HASH = await sign(data, keyArrayBuffer);
			
			sc1("Подписано!", 10);
			//$('#sc1Sign').text(signData);
		});
		
		$('#sc1EncryptFormButton').click(async () => 
		{
			var fileInput = $('#sc1File')[0];
			var keyInput = $('#sc1PubKey')[0];

			if (fileInput.files.length === 0 || keyInput.files.length === 0) 
			{
				sc1("Не указаны файлы");
			    return;
			}

			sc1("Чтение...");
			var file = fileInput.files[0];
			var keyFile = keyInput.files[0];

			//var data = new TextDecoder().decode(await file.arrayBuffer());
			var keyArrayBuffer = new TextDecoder().decode(await keyFile.arrayBuffer());

			//console.log('data='+data.substring(0, 90));
			sc1("Шифрование AES...");
			var { key, iv } = generate_random_key_and_iv(16);
			key = CryptoJS.enc.Hex.parse(key);

			console.log('key='+key);
			//var dataIn = stringToHex(data);
			var dataIn = arrayBufferToHex(await file.arrayBuffer());
			console.log('dataIn='+dataIn.substring(0, 90));
						
			var assCrypted = CryptoJS.AES.encrypt(dataIn, 'assKey', {
			  format: JsonFormatter
			}).toString();
			
			/*
			var assCrypted = CryptoJS.AES.encrypt(dataIn, CryptoJS.enc.Hex.parse(key), 
			{
			    iv: CryptoJS.enc.Hex.parse(iv),
			    mode: CryptoJS.mode.CBC,
			    padding: CryptoJS.pad.Pkcs7
			}).toString();*/

			console.log(assCrypted);
			console.log('assCrypted.len='+assCrypted.length);
			console.log('assCrypted='+assCrypted.substring(0, 90));
			var ivHex = CryptoJS.enc.Hex.parse(iv);

			sc1("Шифрование RSA...");
			var encryptedAssKey = await encryptRSA(key, keyArrayBuffer);
			//var encryptedAssKeyHex = CryptoJS.enc.Hex.parse(encryptedAssKey);
			console.log('encryptedAssKey='+encryptedAssKey);
			var encrypted = SC1_ENCRYPTED = encryptedAssKey+'\n'+ivHex+'\n'+assCrypted;
			
			sc1("Зашифровано!", 10);
		});
		
		$('#sc1DownloadFormButton').click(async () => 
		{
			if (SC1_SIGN_HASH === undefined || SC1_ENCRYPTED === undefined) 
			{
				sc1("Не выполнены предыдущие пункты");
			    return;
			}
			download_file('ПОДПИСЬ.txt', SC1_SIGN_HASH);
			download_file('ШИФРОВАННЫЕ_ДАННЫЕ.bin', SC1_ENCRYPTED);
			sc1("Файлы скачаны", 10);
		});
	});
}

var SC1_DECRYPTED = undefined;

function sc2load()
{
	$(document).ready(() => {
	    $('#formContainer').fadeIn();
	    $('#sc1Form').fadeIn();
		
		$('#sc1DecryptFormButton').click(async () => 
		{
			var fileInput = $('#sc1File')[0];
			var keyInput = $('#sc1PrivKey')[0];

			if (fileInput.files.length === 0 || keyInput.files.length === 0) 
			{
				sc1("Не указаны файлы");
			    return;
			}

			sc1("Чтение...");
			var file = fileInput.files[0];
			var keyFile = keyInput.files[0];

			var data = new TextDecoder().decode(await file.arrayBuffer());
			var keyArrayBuffer = new TextDecoder().decode(await keyFile.arrayBuffer());

			
			var parts = data.split('\n');
			var encryptedAssKey = parts[0];
			var ivHex = parts[1];
			var assCrypted = data.substring(encryptedAssKey.length+1+ivHex.length+1);// parts[2];

			console.log(ivHex);
			
			var iv = CryptoJS.enc.Utf8.parse(ivHex);

			console.log('encryptedAssKey='+encryptedAssKey);
			console.log(iv);

			sc1("Дешифрование RSA...");
			var assKey = await decryptRSA(encryptedAssKey, keyArrayBuffer);

			console.log('assKey='+assKey);
			sc1("Дешифрование AES...");

			console.log('assCrypted.len='+assCrypted.length);
			console.log('assCrypted='+assCrypted.substring(0,90));
			//assCrypted = JSON.parse(assCrypted);
			console.log(assCrypted);
			var decrypted = CryptoJS.AES.decrypt(assCrypted, 'assKey'/*, {
			    iv: iv,
			    mode: CryptoJS.mode.CBC,
			    padding: CryptoJS.pad.Pkcs7
			}*/			, {
						  format: JsonFormatter
						}).toString(CryptoJS.enc.Utf8);

			console.log('decrypted=='+decrypted);
			//decrypted = new TextDecoder().decode(hexToArrayBuffer(decrypted));
		
			//console.log(decrypted.substring(0,90));
			console.log(decrypted);
			//decrypted = decrypted.toString();
			console.log('dataOut='+decrypted.substring(0,90));
			var decryptedData = SC1_DECRYPTED = decrypted;//CryptoJS.enc.Utf8.parse(decrypted);
			console.log('dataOut='+SC1_DECRYPTED.substring(0,90));
			sc1("Дешифровано!", 10);
		});

		$('#sc1VerifyFormButton').click(async () => 
		{
			var fileInput = $('#sc1SignFile')[0];
			var keyInput = $('#sc1PubKey')[0];

			if (fileInput.files.length === 0 || keyInput.files.length === 0) 
			{
				sc1("Не указаны файлы");
			    return;
			}
			
			sc1("Чтение...");
			var file = fileInput.files[0];
			var keyFile = keyInput.files[0];

			var sign = new TextDecoder().decode(await file.arrayBuffer());
			var keyArrayBuffer = new TextDecoder().decode(await keyFile.arrayBuffer());
console.log('sign='+sign);
			sc1("Проверка подписи...");
			if (await verify(SC1_DECRYPTED, sign, keyArrayBuffer))
			{
				sc1("Подпись совпала!", 10);
			}
			else
			{
				sc1("Подпись не совпала!", 10);
			}
		});
		
		$('#sc1DownloadFormButton').click(async () => 
		{
			if (SC1_DECRYPTED === undefined) 
			{
				sc1("Не выполнены предыдущие пункты");
			    return;
			}
			var data = hexToArrayBuffer(SC1_DECRYPTED);
			download_file('ДЕШИФРОВАННЫЕ_ДАННЫЕ', data);
			sc1("Файлы скачаны", 10);
		});
		
		/* 
	    $('#sc1FormButton').click(async () => 
	    {
	        var fileInput = $('#sc1File')[0];
	        var keyInput = $('#sc1Key')[0];

	        if (fileInput.files.length === 0 || keyInput.files.length === 0) 
	    	{
				sc1("Не указаны файлы");
	    	    return;
	    	}
	        
			sc1("Чтение...");
	        var file = fileInput.files[0];
	        var keyFile = keyInput.files[0];

	        var data = new TextDecoder().decode(await file.arrayBuffer());
	        var keyArrayBuffer = new TextDecoder().decode(await keyFile.arrayBuffer());
	        
	        // var dataHash = await sha256(await file.arrayBuffer());
	        var signData = await sign(data, keyArrayBuffer);
	        
			sc1("Отправка...");
	        var formData = new FormData();
	        formData.append('file', new Blob([data], { type: file.type }), file.name);
	        formData.append('sign', signData);

	        var response = await fetch('/verify', 
	        {
	            method: 'POST',
	            body: formData
	        });

	        var result = await response.text();
	        sc1(result);
	    });
	    
	    $('#sc2FormButton').click(async () => 
	    {
			sc1("Запрос сертификата...");
	        var pubData = await fetch('/pub.pem');
	        var pubArrayBuffer = new TextDecoder().decode(await pubData.arrayBuffer());
			sc1("Запрос данных...");
	        var randomData = await fetch('/generate');
	        var randomArrayBuffer = await randomData.arrayBuffer();
	        var signHeader = randomData.headers.get('SIGN');
	        var randomArrayText = new TextDecoder().decode(randomArrayBuffer);

			sc1("Проверка данных...");
	    
	        var isValid = await verify(randomArrayText, signHeader, pubArrayBuffer);
			sc1("isValid=" + isValid);
	    });*/
	});
}
