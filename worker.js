export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/books") {
      const { results } = await env.DB.prepare(
        "SELECT id, title, tagline, age_group, kind, price, cover, in_stock FROM books WHERE hidden = 0 ORDER BY sort_order, id"
      ).all();
      return Response.json(results, { headers: { "Cache-Control": "no-store" } });
    }

    return env.ASSETS.fetch(request);
  },
};
