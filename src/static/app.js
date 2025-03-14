
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
    return encrypt.sign(data, CryptoJS.SHA256, 'sha256');
}

async function verify(message, signature, key) 
{
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(key);
    return encrypt.verify(message, signature, CryptoJS.SHA256);
}

function base64ToHex(base64) 
{
	var binaryString = atob(base64);
	var bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) 
    {
        bytes[i] = binaryString.charCodeAt(i);
    }
    let hexString = '';
    bytes.forEach(byte => 
    {
        const hex = byte.toString(16).padStart(2, '0');
        hexString += hex;
    });
    return hexString;
}


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

			var data = new TextDecoder().decode(await file.arrayBuffer());
			var keyArrayBuffer = new TextDecoder().decode(await keyFile.arrayBuffer());

			sc1("Подпись...");
			var signData = await sign(data, keyArrayBuffer);
			var signHash = SC1_SIGN_HASH = await sha256(new Uint8Array(signData));

			sc1("Подписано!", 10);
			$('#sc1Sign').text(signHash);
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

			var data = new TextDecoder().decode(await file.arrayBuffer());
			var keyArrayBuffer = new TextDecoder().decode(await keyFile.arrayBuffer());

			sc1("Шифрование AES...");
			var { key, iv } = generate_random_key_and_iv(16);
			var assCrypted = atob(CryptoJS.AES.encrypt(data, CryptoJS.enc.Hex.parse(key), 
			{
			    iv: CryptoJS.enc.Hex.parse(iv),
			    mode: CryptoJS.mode.CBC,
			    padding: CryptoJS.pad.Pkcs7
			}).toString());
			
			var ivHex = CryptoJS.enc.Hex.parse(iv);

			sc1("Шифрование RSA...");
			var encryptedAssKey = await encryptRSA(key, keyArrayBuffer);
			//var encryptedAssKeyHex = CryptoJS.enc.Hex.parse(encryptedAssKey);

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
			var assCrypted = parts[2];

			console.log(ivHex);
			
			var iv = CryptoJS.enc.Utf8.parse(ivHex);

			console.log(encryptedAssKey);
			console.log(iv);

			sc1("Дешифрование RSA...");
			var assKey = await decryptRSA(encryptedAssKey, keyArrayBuffer);

			console.log('assKey='+assKey);
			sc1("Дешифрование AES...");
			
			var decrypted = CryptoJS.AES.decrypt(assCrypted, assKey, {
			    iv: iv,
			    mode: CryptoJS.mode.CBC,
			    padding: CryptoJS.pad.Pkcs7
			});

			var decryptedData = SC1_DECRYPTED = decrypted;

			sc1("Дешифровано!", 10);
		});

		$('#sc1VerifyFormButton').click(async () => 
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

			var data = new TextDecoder().decode(await file.arrayBuffer());
			var keyArrayBuffer = new TextDecoder().decode(await keyFile.arrayBuffer());

			sc1("Проверка подписи...");
			if (await verify(SC1_DECRYPTED, keyArrayBuffer))
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
			if (SC1_SIGN_HASH === undefined || SC1_ENCRYPTED === undefined) 
			{
				sc1("Не выполнены предыдущие пункты");
			    return;
			}
			download_file('ПОДПИСЬ.txt', SC1_SIGN_HASH);
			download_file('ШИФРОВАННЫЕ_ДАННЫЕ.bin', SC1_ENCRYPTED);
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
