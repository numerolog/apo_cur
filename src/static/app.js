
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
    var blob = new Blob([data]);

    var url = URL.createObjectURL(blob);

    var a = document.createElement('a');
    a.href = url;
    a.download = filename; 
    document.body.appendChild(a);

    a.click();

    document.body.removeChild(a);

    URL.revokeObjectURL(url);
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

			var data = arrayBufferToHex(await file.arrayBuffer());
			var keyArrayBuffer = new TextDecoder().decode(await keyFile.arrayBuffer());

			sc1("Подпись...");
			SC1_SIGN_HASH = await sign(data, keyArrayBuffer);
			
			sc1("Подписано!", 10);
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

			var keyArrayBuffer = new TextDecoder().decode(await keyFile.arrayBuffer());

			sc1("Шифрование AES...");

			var key = crypto.getRandomValues(new Uint8Array(16));
		    key = CryptoJS.lib.WordArray.create(key);
			
			var dataIn = arrayBufferToHex(await file.arrayBuffer());
						
			var assCrypted = CryptoJS.AES.encrypt(dataIn, key+'', {
			  format: JsonFormatter
			}).toString();

			sc1("Шифрование RSA...");
			// Важный костыль для анигиляции интерпретации hex'кса как содержание другого текста
			key = '_' + key;
			var encryptedAssKey = await encryptRSA(key, keyArrayBuffer);
			
			SC1_ENCRYPTED = encryptedAssKey+'\n'+file.name+'\n'+assCrypted;
			
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
var SC1_FILENAME = undefined;

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
			SC1_FILENAME = parts[1];
			var assCrypted = data.substring(encryptedAssKey.length+1+SC1_FILENAME.length+1);

			sc1("Дешифрование RSA...");
			var assKey = await decryptRSA(encryptedAssKey, keyArrayBuffer);
			assKey = assKey.substring(1);
			
			sc1("Дешифрование AES...");

			SC1_DECRYPTED = CryptoJS.AES.decrypt(assCrypted, assKey, {
			  format: JsonFormatter
			}).toString(CryptoJS.enc.Utf8);

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
			download_file(SC1_FILENAME, data);
			sc1("Файлы скачаны", 10);
		});
	});
}
