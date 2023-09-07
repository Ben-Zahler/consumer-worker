const MILO_HOSTNAME = 'main--milo--adobecom.hlx.live';
const ORIGIN_HOSTNAME = 'main--bens-milo-academy--ben-zahler.hlx.live';
const SUPPORT_HTML = true;


const CRYPTO_PASSWORD = 'sectret partner password';

const removeHtml = (path) => {
	if (path.endsWith('/') || path.endsWith('.plain.html')) return path;

	const split = path.split('/');
	const page = split.pop();
	const [name, ext] = page.split('.');

	if (ext !== 'html') return path;

	split.push(name);
	return split.join('/');
};

async function generateImsUserToken(urlQueryParams) {
	//TODO: is it safe to have client secrets in workers?
	const IMS_CLIENT_SECRET = `xxxxxx`;
	const imsTokenUrl = `https://ims-na1-stg1.adobelogin.com/ims/token/v4?grant_type=authorization_code&client_id=test-milo-gated-access&code=${urlQueryParams.get('code')}&client_secret=${IMS_CLIENT_SECRET}`

	const response = await fetch(imsTokenUrl, {
		method: "POST",
		headers: {
			// "Content-Type": "application/json",
			'Content-Type': 'application/x-www-form-urlencoded',
			// 'X-IMS-ClientId': 'test-milo-gated-access',
		},
	});
	const imsResponse = await response.json();
	console.log('invoked ims token api');
	console.log(imsResponse);
	return imsResponse?.access_token;
}

async function getPartnerData(imsUserToken, partnerData, opts) {
	const req = new Request('https://partnerservices-stage-va6.stage.cloud.adobe.io/apis/partner?email=yugo-stage-spp-gold@yopmail.com&programType=SPP');
	req.headers.set("x-user-token", imsUserToken);
	req.headers.set("Accept", 'application/json');
	req.headers.set("Authorization", "Bearer " + imsUserToken);
	partnerData = await (await fetch(req, opts)).json();
	console.log('requested data from partner service');
	console.log(partnerData);
	return partnerData;
}

function getPartnerTokenCookie(request) {
	let cookie = {};

	let cookieHeader = request.headers.get('Cookie');
	cookieHeader?.split(';').forEach(function (el) {
		if (el?.indexOf('=') > 0) {
			let [key, value] = el.split('=');
			cookie[key.trim()] = value;
		}
	})
	return cookie['partnerToken'];
}

export default {
	async fetch(request) {
		try {
			const url = new URL(request.url);
			const opts = {cf: {}};
			url.hostname = url.pathname.startsWith('/libs')
				? MILO_HOSTNAME
				: ORIGIN_HOSTNAME;
			if (SUPPORT_HTML) url.pathname = removeHtml(url.pathname);
			console.log(url);
			console.log(url.search);
			const urlQueryParams = new URLSearchParams(url.search);
			let partnerData = null;

			if (urlQueryParams.get('code')) {
				// a code parameter indicates that this was invoked after a successful login with IMS
				// we need to now generate the user token
				const imsUserToken = await generateImsUserToken(urlQueryParams);
				//with the ims token, we now invoke the partner service to get the partner data
				partnerData = await getPartnerData(imsUserToken, partnerData, opts);
				if (!partnerData?.program_type) {
					// we will find a more elegant solution for this later
					partnerData.program_type = ' not SPP';
				}
			} else {
				// the user is either anonymous or already logged in... we try to get the partner data from the cookie
				const partnerToken = getPartnerTokenCookie(request);
				console.log(`parsed partner data from cookie ${cookie['partnerToken']}`);
				if (partnerToken) {
					partnerData = {program_type: partnerToken};
				}
			}

			if (url.pathname.startsWith('/protected')) {
				// request is to access a protected resource
				if (!partnerData) {
					// no partner data, we're sending the user to login flow
					console.log('redirecting to login page');
					return Response.redirect('https://adobeid-na1-stg1.services.adobe.com/ims/authorize/v1' +
						'?client_id=test-milo-gated-access' +
						'&redirect_uri=' + request.url +
						'&response_type=code' +
						'&scope=AdobeID%2Copenid&state=blpmtpud1mvkgin728h087f1oi', 302);
				}
				if (!(partnerData?.program_type === 'SPP')) {
					// user is logged in, but not a member of the SPP program -> redirect to 404
					return Response.redirect('https://bens-worker.chris4303.workers.dev/notfound-404', 302);
				}
				//user is logged in and has access to protected content
				console.log('wow, user is successfully logged in!')
			}

			const req = new Request(url, request);
			req.headers.set('x-forwarded-host', req.headers.get('host'));
			req.headers.set('x-byo-cdn-type', 'cloudflare');
			let resp = await fetch(req, opts);
			resp = new Response(resp.body, resp);
			resp.headers.delete('age');
			resp.headers.delete('x-robots-tag');

			//******************
			// since the partnerToken grants access to the portal and also contains sensitive information, we need to encrypt it
			//however, setting a cookie from encrypted bytes needs some more work, we will do that later

			const cryptoKey = await crypto.subtle.generateKey({
				name: 'AES-GCM',
				length: 256
			}, false, [
				'encrypt',
				'decrypt'
			]);
			const iv = crypto.getRandomValues(new Uint8Array(12));
			const algoEncrypt = {
				name: 'AES-GCM',
				iv: iv,
				tagLength: 128
			};

			// const encrypteddata = await crypto.subtle.encrypt(algoEncrypt, cryptoKey, new TextEncoder('utf-8').encode(JSON.stringify(partnerData)));

			// resp.headers.set('Set-Cookie', `partnerToken=${new TextDecoder('utf-8').decode(encrypteddata )}`);

			//******************

			if (partnerData?.program_type) {
				// if we have partner data, we set the cookie so the user does not need to log in again
				resp.headers.set('Set-Cookie', `partnerToken=${partnerData.program_type}`);
			}

			return resp;
		} catch (e) {
			return new Response(e.stack, {status: 500})
		}
	}
}
