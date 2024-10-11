local ipairs      = ipairs
local setmetatable = setmetatable
local tonumber    = tonumber
local type = type
local str_upper = string.upper
local str_lower = string.lower
local re_find     = ngx.re.find
local ngx_var     = ngx.var
local ngx_null    = ngx.null
local ipmatcher   = require("resty.ipmatcher")


local _M = {}
local mt = { __index = _M }
local not_op = "!"


local function in_array(l_v, r_v)
    for _,v in ipairs(r_v) do
        if v == l_v then
            return true
        end
    end
    return false
end


local function has_element(l_v, r_v)
    for _, v in ipairs(l_v) do
        if v == r_v then
            return true
        end
    end
    return false
end

local function ip_match(l_v, r_v)
    return r_v:match(l_v)
end

local compare_funcs = {
    ["=="] = function (l_v, r_v)
        if type(r_v) == "number" then
            l_v = tonumber(l_v)
            return l_v == r_v
        end
        return l_v == r_v
    end,
    ["~="] = function (l_v, r_v)
        if type(r_v) == "number" then
            l_v = tonumber(l_v)
            return l_v ~= r_v
        end
        return l_v ~= r_v
    end,
    [">"] = function (l_v, r_v)
        return tonumber(l_v) > tonumber(r_v)
    end,
    [">="] = function (l_v, r_v)
        return tonumber(l_v) >= tonumber(r_v)
    end,
    ["<"] = function (l_v, r_v)
        return tonumber(l_v) < tonumber(r_v)
    end,
    ["<="] = function (l_v, r_v)
        return tonumber(l_v) <= tonumber(r_v)
    end,
    ["~~"] = function (l_v, r_v)
        return l_v and re_find(l_v, r_v, "jo") and true or false
    end,
    ["~*"] = function (l_v, r_v)
        return l_v and re_find(l_v, r_v, "joi") and true or false
    end,
    ["in"] = in_array,
    ["has"] = has_element,
    ["ipmatch"] = ip_match,
}


local function compare_val(l_v, op, r_v)
    if r_v == ngx_null then
        return false
    end
    local com_fun = compare_funcs[op]
    return com_fun and com_fun(l_v, r_v)
end


local function compile_expr(expr)
    local l_v, op, r_v
    local reverse = false

    if #expr == 4 and expr[2] == not_op then
        reverse = true
        l_v, op, r_v = expr[1], expr[3], expr[4]
    else
        l_v, op, r_v = expr[1], expr[2], expr[3]
    end

    if op then
        op = str_lower(op)
    end

    if not op or not compare_funcs[op] then
        r_v, op = op, "=="
    end

    if not compare_funcs[op] then
        return nil, "invalid operator '" .. op .. "'"
    end

    if op == "ipmatch" then
        if type(r_v) ~= "table" then
            r_v = { r_v }
        end

        local ip, err = ipmatcher.new(r_v)
        if not ip then
            return false, err
        end
        r_v = ip
    end

    return {
        l_v = l_v,
        op = op,
        r_v = r_v,
        reverse = reverse,
    }
end


local logic_ops = {
    ["OR"] = true,
    ["!OR"] = true,
    ["AND"] = true,
    ["!AND"] = true,
}


local function compile(rules)
    local n_rule = #rules
    if n_rule <= 0 then
        return nil, "rule too short"
    end

    local compiled = {
        logic_op = "AND",
        exprs = {},
    }

    if type(rules[1]) == "table" then
        for i, expr in ipairs(rules) do
            local res, err = compile(expr)
            if not res then
                return nil, err
            end
            compiled.exprs[i] = res
        end
        return compiled
    end

    local op = str_upper(rules[1])
    if logic_ops[op] then
        compiled.logic_op = op
        for i = 2, n_rule do
            local res, err = compile(rules[i])
            if not res then
                return nil, err
            end
            compiled.exprs[i - 1] = res
        end
        return compiled
    end

    return compile_expr(rules)
end


function _M.new(rule)
    if not rule or #rule == 0 then
        return setmetatable({}, mt)
    end

    if type(rule[1]) ~= "table" then
        local op = str_upper(rule[1])
        if not logic_ops[op] then
            return nil, "rule should be wrapped inside brackets"
        end
    end

    local compiled, err = compile(rule)
    if not compiled then
        return nil, err
    end

    return setmetatable({ rule = compiled }, mt)
end


local eval
local function eval_and(ctx, exprs, ...)
    for _, expr in ipairs(exprs) do
        if expr.logic_op then
            if not eval(ctx, expr, ...) then
                return false
            end
        else
            local l_v = ctx[expr.l_v]
            if compare_val(l_v, expr.op, expr.r_v) == expr.reverse then
                return false
            end
        end
    end
    return true
end

local function eval_or(ctx, exprs, ...)
    for _, expr in ipairs(exprs) do
        if expr.logic_op then
            if eval(ctx, expr, ...) then
                return true
            end
        else
            local l_v = ctx[expr.l_v]
            if compare_val(l_v, expr.op, expr.r_v) ~= expr.reverse then
                return true
            end
        end
    end
    return false
end

eval = function(ctx, compiled, ...)
    if compiled.logic_op == "AND" then
        return eval_and(ctx, compiled.exprs, ...)
    elseif compiled.logic_op == "OR" then
        return eval_or(ctx, compiled.exprs, ...)
    elseif compiled.logic_op == "!AND" then
        return not eval_and(ctx, compiled.exprs, ...)
    elseif compiled.logic_op == "!OR" then
        return not eval_or(ctx, compiled.exprs, ...)
    else
        error("unknown logic operator: " .. (compiled.logic_op or "nil"))
    end
end


function _M.eval(self, ctx, ...)
    if not self.rule then
        return true
    end

    local ctx = ctx or ngx_var
    if type(ctx) ~= "table" then
        return nil, "bad ctx type"
    end

    return eval(ctx, self.rule, ...)
end

return _M
