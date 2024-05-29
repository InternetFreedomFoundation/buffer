# Buffer

A cloudflare worker that ingestes webhook from Ghost and triggers a deploy hook (after waiting for a specified amount of time) on Cloudflare Pages.

Makes use of Cloudflare KV for persistance.