const ORIGIN_HOSTNAME = 'main--ben-helix-test--ben-zahler.hlx.live';
const IO_HOSTNAME = '14257-partnerportaltest-adapttodemo.adobeioruntime.net';
const IO_API_PATH_PREFIX = '/api/v1';
const SIGN_IN_RESOURCES_PREFIX = '/index';
const FORBIDDEN_PAGE = 'https://main--ben-helix-test--ben-zahler.hlx.live/forbidden';

function getCookieValue(cookieString, cookieName) {
	if (!cookieString) {
		return '';
	}
	const cookieValues = cookieString.split(";").filter((cookie) => {
		return cookie.split("=")[0]?.trim() === cookieName;
	}).map((cookie) => cookie.substring(cookie.indexOf("=") + 1).trim());
	if (cookieValues.length > 0) {
		return cookieValues[0];
	}
}

function createUncachedResponse(response) {
	const newHeaders = new Headers(response.headers);
	newHeaders.set('Cache-Control', 'no-store');
	newHeaders.set('Pragma', 'no-cache');
	newHeaders.set('Expires', '0');
	console.log(`retrieved login page`);
	return new Response(response.body, {
		headers: newHeaders,
		status: response.status,
		statusText: response.statusText,
	});
}

async function redirectToLogin(request) {
	console.log(`requesting login page`);
	const loginReq = new Request(new URL(`https://14257-partnerportaltest-adapttodemo.dev.runtime.adobe.io/index.html`), request);
	const loginOpts = {cf: {}};
	loginReq.headers.set('x-forwarded-host', loginReq.headers.get('host'));
	loginReq.headers.set('x-byo-cdn-type', 'cloudflare');
	const loginResp = (await fetch(loginReq, loginOpts)).clone();
	console.log(`retrieved login page`);
	return createUncachedResponse(loginResp);
}

async function redirectToForbidden(request) {
	console.log(`requesting forbidden page`);
	const forbiddenReq = new Request(new URL(FORBIDDEN_PAGE), request);
	const forbiddenOpts = {cf: {}};
	forbiddenReq.headers.set('x-forwarded-host', forbiddenReq.headers.get('host'));
	forbiddenReq.headers.set('x-byo-cdn-type', 'cloudflare');
	const forbiddenResp = await fetch(forbiddenReq, forbiddenOpts);
	console.log(`retrieved forbidden page`);
	return createUncachedResponse(forbiddenResp);
}

async function fetchFromOrigin(request) {
	const url = new URL(request.url);
	url.hostname = (url.pathname.startsWith(IO_API_PATH_PREFIX) || url.pathname.startsWith(SIGN_IN_RESOURCES_PREFIX))
		? IO_HOSTNAME
		: ORIGIN_HOSTNAME;

	console.log(`${url.pathname} with new host ${url.hostname}`);
	const req = new Request(url, request);
	const opts = {cf: {}};
	req.headers.set('x-forwarded-host', req.headers.get('host'));
	req.headers.set('x-byo-cdn-type', 'cloudflare');


	return await fetch(req, opts);
}

export default {
	async fetch(request, env, ctx) {
		try {
			console.log(`${request.url} start`);
			let cache = caches.default;
			const cacheKey = request.url;
			let resp = request.url.includes('bypass') ? undefined : await cache.match(cacheKey);
			console.log(`${request.url} retrieved from cache`, resp);
			if (!resp) {
				// response not retrieved from cache, so we need to invoke the origin
				resp = await fetchFromOrigin(request);
				console.log(`${cacheKey} retrieved from from origin`, resp);
				ctx.waitUntil(cache.put(cacheKey, resp.clone()));
				console.log(`${cacheKey} added to cache`);
			}
			resp = new Response(resp.body, resp);
			resp.headers.delete('age');
			resp.headers.delete('x-robots-tag');

			const protection = resp.headers.get("protection");
			console.log(`response status ${resp.status}, protection: ${protection}`, new Date());
			if (protection && protection !== 'public') {
				let memberLevel = getCookieValue(request.headers.get('Cookie'), 'adaptToMembershipLevel');
				const adaptToVerification = getCookieValue(request.headers.get('Cookie'), 'adaptToVerification');
				console.log(`existing membership level is ${memberLevel} with verification ${adaptToVerification}`, new Date());
				if (!memberLevel) {
					// send the user to the login page
					return await redirectToLogin(request);
				}
				// user already signed in, we need to verify his access
				const verifyUserResponse = await fetch("https://14257-partnerportaltest-adapttodemo.adobeioruntime.net/api/v1/web/AdapttoService/verifyUser", {
					method: "POST",
					body: JSON.stringify({
						verification: adaptToVerification,
						userData: memberLevel,
					}),
					headers: {
						"Content-type": "application/json; charset=UTF-8"
					}
				})
				console.log(`verify user response status ${verifyUserResponse.status}`);
				if (verifyUserResponse.status !== 200) {
					memberLevel = '';
				}
				if (memberLevel !== 'secret' && protection !== memberLevel) {
					return await redirectToForbidden(request);
				}
				// all good: we can server the response from backend
				resp = createUncachedResponse(resp);
			}
			console.log(`returning response with status ${resp.status}`);
			return resp;
		} catch (e) {
			return new Response(e.stack, {status: 500})
		}
	}
}

