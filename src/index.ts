import { createHmac } from 'node:crypto';
import { DurableObject } from "cloudflare:workers";

interface GhostSignature {
	sha256: string;
	t: string;
}

export interface Env {
	CF_HOOK: string;
	GHOST_WH_SECRET: string;
	BUFFER: DurableObjectNamespace<Buffer>;
}

const COOLING_PERIOD = 2 * 60 * 1000;

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

		let stub = env.BUFFER.getByName("build");
		let res = await stub.triggerBuild()

		if (!res.enqueued) {
			console.log('Build already in queue');
			return new Response(
				JSON.stringify({
					message: 'Build already in queue',
					current_timestamp: currentTime,
					current_alarm: res.alarm,
				}),
			);
		}
		console.log('New Build enqued');
		return new Response(
			JSON.stringify({
				message: 'New Build enqued',
				current_timestamp: currentTime,
				time_remaining: COOLING_PERIOD,
				current_alarm: res.alarm,
			}),
		);
	},
};

// checkSignature function checks if the signature is valid and returns a boolean
async function checkSignature(secret: string, signature: string, req: Request): Promise<Boolean> {
	const payload = await req.json();
	const { sha256: hash, t: timestamp } = signature
		.split(', ')
		.map((x) => x.split('='))
		.reduce((acc, [key, value]) => ({ ...acc, [key]: value }), {}) as GhostSignature
	const hmac = createHmac('sha256', secret).update(`${JSON.stringify(payload)}${timestamp}`).digest('hex');
	console.log('Computed HMAC', hmac);
	console.log('Request Timestamp', timestamp);
	console.log('External HMAC', hash);
	return hmac === hash;
}

export class Buffer extends DurableObject<Env> {
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
	}

	async triggerBuild(): Promise<{ enqueued: boolean; alarm: number | null }> {
		let currentAlarm = await this.ctx.storage.getAlarm();
		if (currentAlarm == null) {
			this.ctx.storage.setAlarm(Date.now() + COOLING_PERIOD);
			return { enqueued: true, alarm: currentAlarm }
		}
		return { enqueued: false, alarm: currentAlarm }
	}

	async alarm() {
		console.log('Alarm triggered at', Date.now());
		let res = await fetch(this.env.CF_HOOK, {
			method: "POST"
		});
		console.log('CF_HOOK response status:', res.status);
	}
}

