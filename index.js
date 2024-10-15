const ORIGIN_HOSTNAME = 'main--adaptto--zagi25.aem.live';
const API_HOSTNAME = '14257-partnerportaltest-adapttodemo.adobeioruntime.net';
const IO_HOSTNAME = '14257-partnerportaltest-adapttodemo.adobeio-static.net';
const IO_API_PATH_PREFIX = '/api/v1';
const SIGN_IN_RESOURCES_PREFIX = '/index';
const FORBIDDEN_PAGE = 'https://main--adaptto--zagi25.aem.live/forbidden';

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

function createNewResponse(response, isCacheable, mustRevalidate, resetCookies, userName, httpStatus) {
	const newHeaders = new Headers(response.headers);
	if(!isCacheable) {
		newHeaders.set('Cache-Control', 'no-store');
	} else {
		const protection = response.headers.get('protection');
		const cacheControl = mustRevalidate && protection ? 'must-revalidate, private, max-age=0' : 'public, max-age=500';
		newHeaders.set('Cache-Control', cacheControl);
		if (userName) {
			newHeaders.set("X-Auth-User", userName);
			newHeaders.set("X-Auth-State", "loggedin");
		}
		newHeaders.set("Vary", "X-Auth-User, Accept-Encoding");
	}
	if (resetCookies) {
		console.log('resetting cookies');
		newHeaders.append('Set-Cookie', `adaptToMemberData=; Secure; SameSite=Strict; Path=/; Max-Age=0;`);
		newHeaders.append('Set-Cookie', `adaptToVerification=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0;`);
	}
	console.log('created new response with headers', newHeaders.get('Cache-Control'));
	return new Response(response.body, {
		headers: newHeaders,
		status: httpStatus || response.status,
		statusText: response.statusText,
	});
}

async function redirectToLogin(request) {
	console.log(`requesting login page`);
  const loginReq = new Request(new URL('https://14257-partnerportaltest-adapttodemo.adobeio-static.net/index.html'), request);
  const loginOpts = { cf: {} };
  loginReq.headers.set("x-forwarded-host", loginReq.headers.get("host"));
  loginReq.headers.set("x-byo-cdn-type", "cloudflare");
  const loginResp = (await fetch(loginReq, loginOpts)).clone();
  console.log(`retrieved login page`);
  return createNewResponse(loginResp, false, false);
}

async function redirectToForbidden(request, resetCookies = false) {
	console.log(`requesting forbidden page`);
	const forbiddenReq = new Request(new URL(FORBIDDEN_PAGE), request);
	const forbiddenOpts = {cf: {}};
	forbiddenReq.headers.set('x-forwarded-host', forbiddenReq.headers.get('host'));
	forbiddenReq.headers.set('x-byo-cdn-type', 'cloudflare');
	const forbiddenResp = await fetch(forbiddenReq, forbiddenOpts);
	console.log(`retrieved forbidden page`);
	return createNewResponse(forbiddenResp, true, true, resetCookies, 403);
}

function getBackendUrl(request) {
	const url = new URL(request.url);
	switch (true) {
		case url.pathname.startsWith(IO_API_PATH_PREFIX):
			url.hostname = API_HOSTNAME;
			break;
		case url.pathname.startsWith(SIGN_IN_RESOURCES_PREFIX):
			url.hostname = IO_HOSTNAME;
			break;
		default:
			url.hostname = ORIGIN_HOSTNAME;
	}
	return url;
}

async function fetchFromOrigin(request, url) {
	console.log(`${url.pathname} with new host ${url.hostname}`);
	const req = new Request(url, request);
	const opts = {cf: {}};
	req.headers.set('x-forwarded-host', req.headers.get('host'));
	req.headers.set('x-byo-cdn-type', 'cloudflare');
	req.headers.set('cache-control', 'no-cache');
  req.headers.set('pragma', 'no-cache');
  req.headers.delete('if-modified-since');

	return await fetch(req, opts);
}

function isProtectedResource(protection) {
	return protection && protection !== 'public';
}

function shouldValidate(protection, memberDataJson, adaptToVerification, url) {
	console.log(`should validate ${protection} ${memberDataJson} ${adaptToVerification} ${url}`);
	const extension = url.pathname.substring(url.pathname.lastIndexOf('.'));
	if(extension.indexOf('/') === -1) {
		return false;
	}
	if(!url.hostname.startsWith(ORIGIN_HOSTNAME)){
		return false;
	}
	if(memberDataJson && adaptToVerification) {
		return true;
	}
	return isProtectedResource(protection);
}

function hasUserAccess(memberData, protection) {
	return memberData.level === 'secret' || protection === memberData.level || !protection || protection === 'public';
}

async function shouldRedirectToLogin(request, adaptToVerification, memberDataJson) {
	const shouldLogin = true;
	let loginRedirect;
	const requestUrl = new URL(request.url);
	if (!requestUrl.pathname.startsWith('/sign-in')) {
		return {};
	}

	if (adaptToVerification && memberDataJson) {
		loginRedirect = new Response('', {
			status: 302,
			headers: {
				'Location': 'https://www.apollopoll.com'
			}
		});
	} else {
		loginRedirect = redirectToLogin(request);
	}
	return { shouldLogin, loginRedirect };
}

export default {
	async fetch(request, env, ctx) {
		try {
			console.log(`${request.url} start`);
			let resetCookies = false;
			let cache = caches.default;
			const cacheKey = request.url;
			let backendUrl = getBackendUrl(request);
			console.log(`backendUrl is ${backendUrl?.hostname}`);
			const memberDataJson = getCookieValue(request.headers.get("Cookie"), "adaptToMemberData");
			const adaptToVerification = getCookieValue(request.headers.get("Cookie"), "adaptToVerification");
			const { shouldLogin, loginRedirect } = await shouldRedirectToLogin(request, adaptToVerification, memberDataJson);
			if (shouldLogin) {
				return await loginRedirect;
			}

			let resp = backendUrl?.hostname === ORIGIN_HOSTNAME ? await cache.match(cacheKey) : null;
			console.log(`${request.url} retrieved from cache`, resp);
			if (!resp) {
				resp = await fetchFromOrigin(request, backendUrl);
				console.log(`${cacheKey} retrieved from from origin`, resp.status);
				ctx.waitUntil(cache.put(cacheKey, resp.clone()));
				console.log(`${cacheKey} added to cache`);
			}

			resp = new Response(resp.body, resp);
			resp.headers.delete("age");
			resp.headers.delete("x-robots-tag");
			const protection = resp.headers.get("protection");
			console.log(`response status ${resp.status}, protection: ${protection}`, /* @__PURE__ */ new Date());
			if (resp.status === 404) {
				return await redirectToForbidden(request);
			}
			let memberData = {};
			if (memberDataJson && adaptToVerification) {
				memberData = JSON.parse(memberDataJson);
			} else if (memberDataJson || adaptToVerification) {
				resetCookies = true;
			}
			if (shouldValidate(protection, memberDataJson, adaptToVerification, backendUrl)) {
				try {
					console.log(`existing membership level is ${memberData.level} with verification ${adaptToVerification}`, /* @__PURE__ */ new Date());
					if (isProtectedResource(protection) && !memberData.level) {
						//return await redirectToLogin(request);
						return new Response('', {
							status: 302,
							headers: {
								'Location': `https://www.apollopoll.com/sign-in?redirect=${request.url}`
							}
						});
					}
					const verifyUserResponse = await fetch("https://14257-partnerportaltest-adapttodemo.adobeioruntime.net/api/v1/web/AdapttoService/verifyUser", {
						method: "POST",
						body: JSON.stringify({
							verification: adaptToVerification,
							userData: memberData
						}),
						headers: {
							"Content-type": "application/json; charset=UTF-8"
						}
					});
					console.log(`verify user response status ${verifyUserResponse.status}`);
					if (verifyUserResponse.status !== 200) {
						memberData = {};
						resetCookies = true;
					}
				} catch (e) {
					console.log(`error parsing member data ${memberDataJson}`);
					resetCookies = true;
				}
			}
			if (!hasUserAccess(memberData, protection)) {
				return await redirectToForbidden(request, resetCookies);
			}
			console.log(`returning response with status ${resp.status}`);
			const isCacheable = !protection || protection === 'public';
			resp = createNewResponse(resp, isCacheable, true, resetCookies, memberData.userName);
			return resp;
		} catch (e) {
			return new Response(e.stack, {status: 500})
		}
	}
}
