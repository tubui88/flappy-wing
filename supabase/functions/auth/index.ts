
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.1/mod.ts"
import { create, getNumericDate, verify } from "https://deno.land/x/djwt@v3.0.1/mod.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.3"

serve(async (req) => {
  const origin = req.headers.get('origin') || '*'
  const corsHeaders = {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Credentials': 'true',
  }

  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    )

    const url = new URL(req.url)
    const path = url.pathname.split('/').pop()

    const { email, password, username, linkedin_url } = await req.json().catch(() => ({}))

    if (path === 'register') {
      if (!email || !password || !username) {
        return new Response(JSON.stringify({ error: 'Missing fields' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          status: 400,
        })
      }

      const salt = bcrypt.genSaltSync(10)
      const password_hash = bcrypt.hashSync(password, salt)

      const { data, error } = await supabase
        .schema('flappy_xwing')
        .from('users')
        .insert([{ email, username, linkedin_url, password_hash }])
        .select()
        .single()

      if (error) throw error

      return new Response(JSON.stringify({ success: true, user: data }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 200,
      })
    }

    if (path === 'login') {
      if (!email || !password) {
        return new Response(JSON.stringify({ error: 'Missing email or password' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          status: 400,
        })
      }

      // Check users table first
      let userRes = await supabase
        .schema('flappy_xwing')
        .from('users')
        .select('*')
        .eq('email', email)
        .single()

      let isAdmin = false

      if (userRes.error) {
        // Fallback to admins table
        userRes = await supabase
          .schema('flappy_xwing')
          .from('admins')
          .select('*')
          .eq('email', email)
          .single()
        
        if (userRes.error) {
          return new Response(JSON.stringify({ error: 'User not found' }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            status: 404,
          })
        }
        isAdmin = true
      }

      const user = userRes.data
      const isValid = bcrypt.compareSync(password, user.password_hash)

      if (!isValid) {
        return new Response(JSON.stringify({ error: 'Invalid password' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          status: 401,
        })
      }

      const secret = Deno.env.get('ADMIN_JWT_SECRET')
      if (!secret) throw new Error('JWT Secret missing')

      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-512" },
        false,
        ["sign", "verify"]
      )

      const jwt = await create(
        { alg: "HS512", typ: "JWT" },
        { email: user.email, id: user.id, role: isAdmin ? 'admin' : 'user', exp: getNumericDate(60 * 60 * 24) },
        key
      )

      const headers = new Headers({
        ...corsHeaders,
        'Content-Type': 'application/json',
      })
      
      headers.append('Set-Cookie', `auth_session=${jwt}; HttpOnly; Secure; Path=/; Max-Age=${60 * 60 * 24}`)

      return new Response(JSON.stringify({ success: true, user: { email: user.email, id: user.id, isAdmin } }), {
        headers,
        status: 200,
      })
    }

    if (path === 'me') {
      const cookieHeader = req.headers.get('Cookie')
      const match = cookieHeader?.match(/auth_session=([^;]+)/)
      const token = match ? match[1] : null

      if (!token) {
        return new Response(JSON.stringify({ error: 'Not authenticated' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          status: 401,
        })
      }

      const secret = Deno.env.get('ADMIN_JWT_SECRET')
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret!),
        { name: "HMAC", hash: "SHA-512" },
        false,
        ["sign", "verify"]
      )

      try {
        const payload = await verify(token, key)
        return new Response(JSON.stringify({ success: true, user: payload }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          status: 200,
        })
      } catch (err) {
        return new Response(JSON.stringify({ error: 'Invalid token' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          status: 401,
        })
      }
    }

    if (path === 'logout') {
      const headers = new Headers({
        ...corsHeaders,
        'Content-Type': 'application/json',
      })
      headers.append('Set-Cookie', `auth_session=; HttpOnly; Secure; Path=/; Max-Age=0`)
      return new Response(JSON.stringify({ success: true }), { headers, status: 200 })
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: 404,
    })

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: 500,
    })
  }
})
