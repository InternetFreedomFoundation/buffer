import { createHmac } from 'node:crypto';

export interface Env {
	ghost_build: KVNamespace;
	CF_HOOK: string;
	GHOST_WH_SECRET: string;
}

export interface metadata {
	last_build_triggered_at: string;
	hook_status: string;
}

const COOLING_PERIOD = 1000 * 25;

export default {
	async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const currentTime = Date.now();
		const signature = req.headers.get('x-ghost-signature');

		if (signature == null) {
			return new Response('Unauthorized', { status: 401 });
		}

		const validRequest = await checkSignature(env.GHOST_WH_SECRET, signature!, req);
		if (!validRequest) {
			return new Response('Unauthorized', { status: 401 });
		}
		console.log("Signature Verified, Valid Request")

		let { value, metadata } = await env.ghost_build.getWithMetadata<metadata>('timestamp');
		if (value == null) {
			value = Date.now().toString();
			await env.ghost_build.put('timestamp', value);
		}
		const timestamp = parseInt(value);

		if (currentTime < timestamp + COOLING_PERIOD) {
			console.log('Build already in queue');
			return new Response(
				JSON.stringify({
					message: 'Build already in queue',
					current_timestamp: currentTime,
					last_build: timestamp,
					time_remaining: timestamp + COOLING_PERIOD - currentTime,
					metadata: {
						last_build_triggered_at: metadata?.last_build_triggered_at,
						hook_status: metadata?.hook_status,
					},
				}),
			);
		}

		await env.ghost_build.put('timestamp', currentTime.toString(), {
			metadata: metadata,
		});
		ctx.waitUntil(triggerBuild(env, currentTime.toString()));
		console.log('New Build enqued');
		return new Response(
			JSON.stringify({
				message: 'New Build enqued',
				current_timestamp: currentTime,
				last_build: timestamp,
				time_remaining: COOLING_PERIOD,
				metadata: {
					last_build_triggered_at: metadata?.last_build_triggered_at,
					hook_status: metadata?.hook_status,
				},
			}),
		);
	},
};

async function triggerBuild(env: Env, timestamp: string) {
	console.log('Queue triggered');
	await new Promise((r) => setTimeout(r, COOLING_PERIOD));
	const res = await fetch(env.CF_HOOK, {
		method: 'POST',
	});
	await env.ghost_build.put('timestamp', timestamp, {
		metadata: <metadata>{
			last_build_triggered_at: Date.now().toString(),
			hook_status: res.statusText,
		},
	});
	console.log('Queue processed');
}

// checkSignature function checks if the signature is valid and returns a boolean
async function checkSignature(secret: string, signature: string, req: Request): Promise<Boolean> {
	const payload = await req.json();
	const [externalHmac, timestamp] = signature.split(',');
	const hmac = createHmac('sha256', secret).update(JSON.stringify(payload)).digest('hex');
	console.log('Computed HMAC', hmac);
	console.log('Request Timestamp', timestamp);
	console.log('External HMAC', externalHmac);
	return `sha256=${hmac}` === externalHmac;
}
