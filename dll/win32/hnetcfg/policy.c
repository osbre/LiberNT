/*
 * Copyright 2009 Hans Leidekker for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdio.h>
#include <limits.h>

#define COBJMACROS

#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "ole2.h"
#include "netfw.h"

#include "wine/debug.h"
#include "hnetcfg_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(hnetcfg);

typedef struct fw_policy
{
    INetFwPolicy INetFwPolicy_iface;
    LONG refs;
} fw_policy;

static inline fw_policy *impl_from_INetFwPolicy( INetFwPolicy *iface )
{
    return CONTAINING_RECORD(iface, fw_policy, INetFwPolicy_iface);
}

typedef struct fw_policy2
{
    INetFwPolicy2 INetFwPolicy2_iface;
    INetFwRules   *fw_policy2_rules;
    LONG refs;
} fw_policy2;

static inline fw_policy2 *impl_from_INetFwPolicy2( INetFwPolicy2 *iface )
{
    return CONTAINING_RECORD(iface, fw_policy2, INetFwPolicy2_iface);
}

typedef struct fw_rule
{
    INetFwRule INetFwRule_iface;
    LONG refs;
    BSTR name;
    BSTR description;
    BSTR application;
    BSTR service;
    BSTR local_ports;
    BSTR remote_ports;
    BSTR local_addresses;
    BSTR remote_addresses;
    BSTR icmp_types;
    BSTR interface_types;
    BSTR grouping;
    VARIANT interfaces;
    LONG protocol;
    NET_FW_RULE_DIRECTION direction;
    LONG profiles;
    NET_FW_ACTION action;
    VARIANT_BOOL enabled;
    VARIANT_BOOL edge_traversal;
    BOOL has_direction;
    BOOL has_action;
    BOOL has_protocol;
    BOOL has_profiles;
} fw_rule;

static inline fw_rule *impl_from_INetFwRule( INetFwRule *iface )
{
    return CONTAINING_RECORD(iface, fw_rule, INetFwRule_iface);
}

static HRESULT fw_rule_get_string(BSTR value, BSTR *out)
{
    if (!out) return E_POINTER;
    *out = value ? SysAllocStringLen(value, SysStringLen(value)) : SysAllocString(L"");
    return *out ? S_OK : E_OUTOFMEMORY;
}

static HRESULT fw_rule_put_string(BSTR *target, BSTR value)
{
    BSTR copy;

    if (!value) return E_INVALIDARG;
    copy = SysAllocStringLen(value, SysStringLen(value));
    if (!copy) return E_OUTOFMEMORY;
    SysFreeString(*target);
    *target = copy;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_QueryInterface(
    INetFwRule *iface,
    REFIID riid,
    void **object)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    TRACE("%p %s %p\n", This, debugstr_guid( riid ), object );

    if ( IsEqualGUID( riid, &IID_INetFwRule ) ||
         IsEqualGUID( riid, &IID_IDispatch ) ||
         IsEqualGUID( riid, &IID_IUnknown ) )
    {
        *object = iface;
    }
    else
    {
        FIXME("interface %s not implemented\n", debugstr_guid(riid));
        return E_NOINTERFACE;
    }
    INetFwRule_AddRef( iface );
    return S_OK;
}

static ULONG WINAPI netfw_rule_AddRef(
    INetFwRule *iface )
{
    fw_rule *This = impl_from_INetFwRule( iface );
    return InterlockedIncrement( &This->refs );
}

static ULONG WINAPI netfw_rule_Release(
    INetFwRule *iface )
{
    fw_rule *This = impl_from_INetFwRule( iface );
    LONG refs = InterlockedDecrement( &This->refs );
    if (!refs)
    {
        TRACE("destroying %p\n", This);
        SysFreeString(This->name);
        SysFreeString(This->description);
        SysFreeString(This->application);
        SysFreeString(This->service);
        SysFreeString(This->local_ports);
        SysFreeString(This->remote_ports);
        SysFreeString(This->local_addresses);
        SysFreeString(This->remote_addresses);
        SysFreeString(This->icmp_types);
        SysFreeString(This->interface_types);
        SysFreeString(This->grouping);
        VariantClear(&This->interfaces);
        free( This );
    }
    return refs;
}

static HRESULT WINAPI netfw_rule_GetTypeInfoCount(
    INetFwRule *iface,
    UINT *pctinfo )
{
    fw_rule *This = impl_from_INetFwRule( iface );

    TRACE("%p %p\n", This, pctinfo);
    *pctinfo = 1;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_GetTypeInfo(
    INetFwRule *iface,
    UINT iTInfo,
    LCID lcid,
    ITypeInfo **ppTInfo)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    TRACE("%p %u %lu %p\n", This, iTInfo, lcid, ppTInfo);
    return get_typeinfo( INetFwRule_tid, ppTInfo );
}

static HRESULT WINAPI netfw_rule_GetIDsOfNames(
    INetFwRule *iface,
    REFIID riid,
    LPOLESTR *rgszNames,
    UINT cNames,
    LCID lcid,
    DISPID *rgDispId)
{
    fw_rule *This = impl_from_INetFwRule( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %s %p %u %lu %p\n", This, debugstr_guid(riid), rgszNames, cNames, lcid, rgDispId);

    hr = get_typeinfo( INetFwRule_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_GetIDsOfNames( typeinfo, rgszNames, cNames, rgDispId );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI netfw_rule_Invoke(
    INetFwRule *iface,
    DISPID dispIdMember,
    REFIID riid,
    LCID lcid,
    WORD wFlags,
    DISPPARAMS *pDispParams,
    VARIANT *pVarResult,
    EXCEPINFO *pExcepInfo,
    UINT *puArgErr)
{
    fw_rule *This = impl_from_INetFwRule( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %ld %s %ld %d %p %p %p %p\n", This, dispIdMember, debugstr_guid(riid),
          lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);

    hr = get_typeinfo( INetFwRule_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_Invoke( typeinfo, &This->INetFwRule_iface, dispIdMember,
                               wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI netfw_rule_get_Name(
    INetFwRule *iface,
    BSTR *name)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_get_string(This->name, name);
}

static HRESULT WINAPI netfw_rule_put_Name(
    INetFwRule *iface,
    BSTR name)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_put_string(&This->name, name);
}

static HRESULT WINAPI netfw_rule_get_Description(
    INetFwRule *iface,
    BSTR *desc)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_get_string(This->description, desc);
}

static HRESULT WINAPI netfw_rule_put_Description(
    INetFwRule *iface,
    BSTR desc)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_put_string(&This->description, desc);
}

static HRESULT WINAPI netfw_rule_get_ApplicationName(
    INetFwRule *iface,
    BSTR *app)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_get_string(This->application, app);
}

static HRESULT WINAPI netfw_rule_put_ApplicationName(
    INetFwRule *iface,
    BSTR app)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_put_string(&This->application, app);
}

static HRESULT WINAPI netfw_rule_get_ServiceName(
    INetFwRule *iface,
    BSTR *service)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_get_string(This->service, service);
}

static HRESULT WINAPI netfw_rule_put_ServiceName(
    INetFwRule *iface,
    BSTR service)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_put_string(&This->service, service);
}

static HRESULT WINAPI netfw_rule_get_Protocol(
    INetFwRule *iface,
    LONG *protocol)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    if (!protocol) return E_POINTER;
    *protocol = This->protocol;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_Protocol(
    INetFwRule *iface,
    LONG protocol)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    This->protocol = protocol;
    This->has_protocol = TRUE;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_get_LocalPorts(
    INetFwRule *iface,
    BSTR *ports)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_get_string(This->local_ports, ports);
}

static HRESULT WINAPI netfw_rule_put_LocalPorts(
    INetFwRule *iface,
    BSTR ports)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_put_string(&This->local_ports, ports);
}

static HRESULT WINAPI netfw_rule_get_RemotePorts(
    INetFwRule *iface,
    BSTR *ports)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_get_string(This->remote_ports, ports);
}

static HRESULT WINAPI netfw_rule_put_RemotePorts(
    INetFwRule *iface,
    BSTR ports)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_put_string(&This->remote_ports, ports);
}

static HRESULT WINAPI netfw_rule_get_LocalAddresses(
    INetFwRule *iface,
    BSTR *addresses)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_get_string(This->local_addresses, addresses);
}

static HRESULT WINAPI netfw_rule_put_LocalAddresses(
    INetFwRule *iface,
    BSTR addresses)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_put_string(&This->local_addresses, addresses);
}

static HRESULT WINAPI netfw_rule_get_RemoteAddresses(
    INetFwRule *iface,
    BSTR *addresses)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_get_string(This->remote_addresses, addresses);
}

static HRESULT WINAPI netfw_rule_put_RemoteAddresses(
    INetFwRule *iface,
    BSTR addresses)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_put_string(&This->remote_addresses, addresses);
}

static HRESULT WINAPI netfw_rule_get_IcmpTypesAndCodes(
    INetFwRule *iface,
    BSTR *codes)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_get_string(This->icmp_types, codes);
}

static HRESULT WINAPI netfw_rule_put_IcmpTypesAndCodes(
    INetFwRule *iface,
    BSTR codes)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_put_string(&This->icmp_types, codes);
}

static HRESULT WINAPI netfw_rule_get_Direction(
    INetFwRule *iface,
    NET_FW_RULE_DIRECTION *dir)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    if (!dir) return E_POINTER;
    *dir = This->direction;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_Direction(
    INetFwRule *iface,
    NET_FW_RULE_DIRECTION dir)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    This->direction = dir;
    This->has_direction = TRUE;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_get_Interfaces(
    INetFwRule *iface,
    VARIANT *interfaces)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    if (!interfaces) return E_POINTER;
    return VariantCopy(interfaces, &This->interfaces);
}

static HRESULT WINAPI netfw_rule_put_Interfaces(
    INetFwRule *iface,
    VARIANT interfaces)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return VariantCopy(&This->interfaces, &interfaces);
}

static HRESULT WINAPI netfw_rule_get_InterfaceTypes(
    INetFwRule *iface,
    BSTR *types)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_get_string(This->interface_types, types);
}

static HRESULT WINAPI netfw_rule_put_InterfaceTypes(
    INetFwRule *iface,
    BSTR types)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_put_string(&This->interface_types, types);
}

static HRESULT WINAPI netfw_rule_get_Enabled(
    INetFwRule *iface,
    VARIANT_BOOL *enabled)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    if (!enabled) return E_POINTER;
    *enabled = This->enabled;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_Enabled(
    INetFwRule *iface,
    VARIANT_BOOL enabled)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    This->enabled = enabled ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_get_Grouping(
    INetFwRule *iface,
    BSTR *grouping)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_get_string(This->grouping, grouping);
}

static HRESULT WINAPI netfw_rule_put_Grouping(
    INetFwRule *iface,
    BSTR grouping)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    return fw_rule_put_string(&This->grouping, grouping);
}

static HRESULT WINAPI netfw_rule_get_Profiles(
    INetFwRule *iface,
    LONG *profiles)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    if (!profiles) return E_POINTER;
    *profiles = This->profiles;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_Profiles(
    INetFwRule *iface,
    LONG profiles)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    This->profiles = profiles;
    This->has_profiles = TRUE;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_get_EdgeTraversal(
    INetFwRule *iface,
    VARIANT_BOOL *enabled)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    if (!enabled) return E_POINTER;
    *enabled = This->edge_traversal;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_EdgeTraversal(
    INetFwRule *iface,
    VARIANT_BOOL enabled)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    This->edge_traversal = enabled ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_get_Action(
    INetFwRule *iface,
    NET_FW_ACTION *action)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    if (!action) return E_POINTER;
    *action = This->action;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_Action(
    INetFwRule *iface,
    NET_FW_ACTION action)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    This->action = action;
    This->has_action = TRUE;
    return S_OK;
}

static const struct INetFwRuleVtbl fw_rule_vtbl =
{
    netfw_rule_QueryInterface,
    netfw_rule_AddRef,
    netfw_rule_Release,
    netfw_rule_GetTypeInfoCount,
    netfw_rule_GetTypeInfo,
    netfw_rule_GetIDsOfNames,
    netfw_rule_Invoke,
    netfw_rule_get_Name,
    netfw_rule_put_Name,
    netfw_rule_get_Description,
    netfw_rule_put_Description,
    netfw_rule_get_ApplicationName,
    netfw_rule_put_ApplicationName,
    netfw_rule_get_ServiceName,
    netfw_rule_put_ServiceName,
    netfw_rule_get_Protocol,
    netfw_rule_put_Protocol,
    netfw_rule_get_LocalPorts,
    netfw_rule_put_LocalPorts,
    netfw_rule_get_RemotePorts,
    netfw_rule_put_RemotePorts,
    netfw_rule_get_LocalAddresses,
    netfw_rule_put_LocalAddresses,
    netfw_rule_get_RemoteAddresses,
    netfw_rule_put_RemoteAddresses,
    netfw_rule_get_IcmpTypesAndCodes,
    netfw_rule_put_IcmpTypesAndCodes,
    netfw_rule_get_Direction,
    netfw_rule_put_Direction,
    netfw_rule_get_Interfaces,
    netfw_rule_put_Interfaces,
    netfw_rule_get_InterfaceTypes,
    netfw_rule_put_InterfaceTypes,
    netfw_rule_get_Enabled,
    netfw_rule_put_Enabled,
    netfw_rule_get_Grouping,
    netfw_rule_put_Grouping,
    netfw_rule_get_Profiles,
    netfw_rule_put_Profiles,
    netfw_rule_get_EdgeTraversal,
    netfw_rule_put_EdgeTraversal,
    netfw_rule_get_Action,
    netfw_rule_put_Action,
};

HRESULT NetFwRule_create( IUnknown *outer, void **obj )
{
    fw_rule *rule;

    TRACE("(%p)\n", obj);

    rule = calloc(1, sizeof(*rule));
    if (!rule) return E_OUTOFMEMORY;

    rule->INetFwRule_iface.lpVtbl = &fw_rule_vtbl;
    rule->refs = 1;
    VariantInit(&rule->interfaces);
    rule->protocol = 256;
    rule->profiles = NET_FW_PROFILE2_ALL;

    *obj = &rule->INetFwRule_iface;

    TRACE("returning iface %p\n", *obj);
    return S_OK;
}

typedef struct fw_rules
{
    INetFwRules INetFwRules_iface;
    LONG refs;
} fw_rules;

static inline fw_rules *impl_from_INetFwRules( INetFwRules *iface )
{
    return CONTAINING_RECORD(iface, fw_rules, INetFwRules_iface);
}

#define FIREWALL_RULES_KEY L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
#define FIREWALL_RULE_MAX_CHARS 4096

static HRESULT fw_rule_append(WCHAR *buffer, SIZE_T capacity, SIZE_T *length, PCWSTR text)
{
    SIZE_T text_length = wcslen(text);

    if (*length >= capacity || text_length >= capacity - *length)
        return E_INVALIDARG;
    memcpy(buffer + *length, text, text_length * sizeof(WCHAR));
    *length += text_length;
    buffer[*length] = 0;
    return S_OK;
}

static HRESULT fw_rule_append_field(WCHAR *buffer, SIZE_T capacity, SIZE_T *length,
                                    PCWSTR field, PCWSTR value)
{
    HRESULT hr;

    if (FAILED(hr = fw_rule_append(buffer, capacity, length, field)) ||
        FAILED(hr = fw_rule_append(buffer, capacity, length, L"=")) ||
        FAILED(hr = fw_rule_append(buffer, capacity, length, value)) ||
        FAILED(hr = fw_rule_append(buffer, capacity, length, L"|")))
        return hr;
    return S_OK;
}

static BOOL fw_rule_text_supported(BSTR text)
{
    UINT length, index;

    if (!text) return TRUE;
    length = SysStringLen(text);
    if (length >= FIREWALL_RULE_MAX_CHARS || wcslen(text) != length)
        return FALSE;
    for (index = 0; index < length; index++)
    {
        if (text[index] == L'|' || text[index] < 0x20)
            return FALSE;
    }
    return TRUE;
}

static BOOL fw_rule_name_supported(BSTR name)
{
    UINT length;

    if (!name) return FALSE;
    length = SysStringLen(name);
    return length != 0 && length < FIREWALL_RULE_MAX_CHARS && wcslen(name) == length;
}

static BOOL fw_rule_parse_number(PCWSTR text, SIZE_T length, UINT32 maximum, UINT32 *value)
{
    SIZE_T index;
    UINT32 result = 0;

    if (!length) return FALSE;
    for (index = 0; index < length; index++)
    {
        UINT32 digit;

        if (text[index] < L'0' || text[index] > L'9')
            return FALSE;
        digit = text[index] - L'0';
        if (result > (maximum - digit) / 10)
            return FALSE;
        result = result * 10 + digit;
    }
    *value = result;
    return TRUE;
}

static BOOL fw_rule_valid_ports(BSTR ports, UINT32 *port_count)
{
    SIZE_T length, start = 0, end, dash;
    UINT32 number;

    *port_count = 0;
    if (!ports || !ports[0] || !wcscmp(ports, L"*"))
    {
        *port_count = 1;
        return TRUE;
    }
    if (!fw_rule_text_supported(ports))
        return FALSE;

    length = SysStringLen(ports);
    while (start < length)
    {
        end = start;
        dash = length;
        while (end < length && ports[end] != L',')
        {
            if (ports[end] == L'-')
            {
                if (dash != length)
                    return FALSE;
                dash = end;
            }
            end++;
        }
        if (dash == length)
        {
            if (!fw_rule_parse_number(ports + start, end - start, 65535, &number))
                return FALSE;
        }
        else
        {
            UINT32 first, last;

            if (!fw_rule_parse_number(ports + start, dash - start, 65535, &first) ||
                !fw_rule_parse_number(ports + dash + 1, end - dash - 1, 65535, &last) ||
                first > last)
                return FALSE;
        }
        if (++*port_count > 16)
            return FALSE;
        if (end == length)
            return TRUE;
        start = end + 1;
    }
    return FALSE;
}

static BOOL fw_rule_valid_ipv4(BSTR address)
{
    SIZE_T length, start = 0, end, slash, index;
    UINT32 octet, prefix;

    if (!address || !address[0] || !wcscmp(address, L"*"))
        return TRUE;
    if (!fw_rule_text_supported(address))
        return FALSE;

    length = SysStringLen(address);
    slash = length;
    for (index = 0; index < length; index++)
    {
        if (address[index] == L',')
            return FALSE;
        if (address[index] == L'/')
        {
            if (slash != length)
                return FALSE;
            slash = index;
        }
    }

    for (index = 0; index < 4; index++)
    {
        end = start;
        while (end < slash && address[end] != L'.')
            end++;
        if (end == start || end - start > 3 ||
            !fw_rule_parse_number(address + start, end - start, 255, &octet))
            return FALSE;
        if (index < 3)
        {
            if (end == slash)
                return FALSE;
            start = end + 1;
        }
        else if (end != slash)
            return FALSE;
    }

    if (slash == length)
        return TRUE;
    if (fw_rule_parse_number(address + slash + 1, length - slash - 1, 32, &prefix))
        return TRUE;

    start = slash + 1;
    for (index = 0; index < 4; index++)
    {
        end = start;
        while (end < length && address[end] != L'.')
            end++;
        if (end == start || end - start > 3 ||
            !fw_rule_parse_number(address + start, end - start, 255, &octet))
            return FALSE;
        if (index < 3)
        {
            if (end == length)
                return FALSE;
            start = end + 1;
        }
        else if (end != length)
            return FALSE;
    }
    return TRUE;
}

static HRESULT fw_rule_serialize(fw_rule *rule, WCHAR *buffer, SIZE_T capacity)
{
    WCHAR number[16];
    SIZE_T length = 0;
    UINT32 local_port_count, remote_port_count;
    LONG profiles;
    LONG protocol;
    HRESULT hr;

    buffer[0] = 0;
    if (!fw_rule_name_supported(rule->name) ||
        !rule->has_direction || !rule->has_action)
        return E_INVALIDARG;
    if (rule->direction != NET_FW_RULE_DIR_IN && rule->direction != NET_FW_RULE_DIR_OUT)
        return E_INVALIDARG;
    if (rule->action != NET_FW_ACTION_ALLOW && rule->action != NET_FW_ACTION_BLOCK)
        return E_INVALIDARG;
    if (!fw_rule_text_supported(rule->description) ||
        !fw_rule_text_supported(rule->application) ||
        !fw_rule_text_supported(rule->service) ||
        !fw_rule_text_supported(rule->local_ports) ||
        !fw_rule_text_supported(rule->remote_ports) ||
        !fw_rule_text_supported(rule->local_addresses) ||
        !fw_rule_text_supported(rule->remote_addresses) ||
        !fw_rule_text_supported(rule->icmp_types) ||
        !fw_rule_text_supported(rule->interface_types) ||
        !fw_rule_text_supported(rule->grouping))
        return E_INVALIDARG;

    if ((rule->service && rule->service[0] && wcscmp(rule->service, L"*")) ||
        (rule->icmp_types && rule->icmp_types[0] && wcscmp(rule->icmp_types, L"*")) ||
        (rule->interface_types && rule->interface_types[0] &&
         _wcsicmp(rule->interface_types, L"All")) ||
        (rule->interfaces.vt != VT_EMPTY) ||
        rule->edge_traversal == VARIANT_TRUE)
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);

    if (!fw_rule_valid_ports(rule->local_ports, &local_port_count) ||
        !fw_rule_valid_ports(rule->remote_ports, &remote_port_count) ||
        !fw_rule_valid_ipv4(rule->local_addresses) ||
        !fw_rule_valid_ipv4(rule->remote_addresses))
        return E_INVALIDARG;
    if (local_port_count * remote_port_count > 64)
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    if (rule->application && SysStringLen(rule->application) >= 1024)
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    if (rule->enabled != VARIANT_TRUE && rule->enabled != VARIANT_FALSE)
        return E_INVALIDARG;
    if (rule->edge_traversal != VARIANT_TRUE && rule->edge_traversal != VARIANT_FALSE)
        return E_INVALIDARG;

    protocol = rule->has_protocol ? rule->protocol : 256;
    if (protocol < 0 || protocol > 256)
        return E_INVALIDARG;
    if (((rule->local_ports && rule->local_ports[0] &&
          wcscmp(rule->local_ports, L"*")) ||
         (rule->remote_ports && rule->remote_ports[0] &&
          wcscmp(rule->remote_ports, L"*"))) &&
        protocol != 6 && protocol != 17)
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);

    profiles = rule->has_profiles ? rule->profiles : NET_FW_PROFILE2_ALL;
    if (profiles != NET_FW_PROFILE2_ALL &&
        (profiles <= 0 || (profiles & ~7) != 0))
        return E_INVALIDARG;

    if (FAILED(hr = fw_rule_append(buffer, capacity, &length, L"v2.10|")) ||
        FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"Action",
                                         rule->action == NET_FW_ACTION_ALLOW ? L"Allow" : L"Block")) ||
        FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"Active",
                                         rule->enabled == VARIANT_TRUE ? L"TRUE" : L"FALSE")) ||
        FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"Dir",
                                         rule->direction == NET_FW_RULE_DIR_IN ? L"In" : L"Out")))
        return hr;

    swprintf(number, ARRAYSIZE(number), L"%ld", protocol);
    if (FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"Protocol", number)))
        return hr;

    if (rule->local_ports && rule->local_ports[0] && wcscmp(rule->local_ports, L"*") &&
        FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"LPort", rule->local_ports)))
        return hr;
    if (rule->remote_ports && rule->remote_ports[0] && wcscmp(rule->remote_ports, L"*") &&
        FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"RPort", rule->remote_ports)))
        return hr;
    if (rule->local_addresses && rule->local_addresses[0] &&
        wcscmp(rule->local_addresses, L"*") &&
        FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"LA4", rule->local_addresses)))
        return hr;
    if (rule->remote_addresses && rule->remote_addresses[0] &&
        wcscmp(rule->remote_addresses, L"*") &&
        FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"RA4", rule->remote_addresses)))
        return hr;
    if (rule->application && rule->application[0] &&
        FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"App", rule->application)))
        return hr;
    if (rule->description && rule->description[0] &&
        FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"Desc", rule->description)))
        return hr;
    if (rule->grouping && rule->grouping[0] &&
        FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"EmbedCtxt", rule->grouping)))
        return hr;

    if (profiles != NET_FW_PROFILE2_ALL)
    {
        if ((profiles & NET_FW_PROFILE2_DOMAIN) &&
            FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"Profile", L"Domain")))
            return hr;
        if ((profiles & NET_FW_PROFILE2_PRIVATE) &&
            FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"Profile", L"Private")))
            return hr;
        if ((profiles & NET_FW_PROFILE2_PUBLIC) &&
            FAILED(hr = fw_rule_append_field(buffer, capacity, &length, L"Profile", L"Public")))
            return hr;
    }
    return S_OK;
}

static HRESULT fw_rules_open_registry(BOOL create, REGSAM access, HKEY *key)
{
    LONG error;

    if (create)
        error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, FIREWALL_RULES_KEY, 0, NULL,
                                REG_OPTION_NON_VOLATILE, access,
                                NULL, key, NULL);
    else
        error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, FIREWALL_RULES_KEY, 0,
                              access, key);

    if (error == ERROR_FILE_NOT_FOUND && !create)
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    return error == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(error);
}

static HRESULT fw_rule_parse_value(INetFwRule *rule, PCWSTR text)
{
    PCWSTR position = text;
    LONG profiles = 0;
    BOOL have_profiles = FALSE;

    while (*position)
    {
        PCWSTR end = wcschr(position, L'|');
        PCWSTR equals;
        SIZE_T field_length, value_length;
        WCHAR *field;
        HRESULT hr = S_OK;

        if (!end)
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        if (end == position)
        {
            position++;
            continue;
        }
        if (end - position >= 4 && position[0] == L'v' && position[1] == L'2' &&
            position[2] == L'.')
        {
            PCWSTR version = position + 3;

            while (version < end)
            {
                if (*version < L'0' || *version > L'9')
                    return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                version++;
            }
            position = end + 1;
            continue;
        }
        equals = wcschr(position, L'=');
        if (!equals || equals >= end)
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        field_length = equals - position;
        value_length = end - equals - 1;
        if (!value_length &&
            !((field_length == 4 && !_wcsnicmp(position, L"Desc", field_length)) ||
              (field_length == 9 && !_wcsnicmp(position, L"EmbedCtxt", field_length))))
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        field = malloc((field_length + 1) * sizeof(WCHAR));
        if (!field) return E_OUTOFMEMORY;
        memcpy(field, position, field_length * sizeof(WCHAR));
        field[field_length] = 0;

        if (!_wcsicmp(field, L"Action"))
        {
            if (value_length == 5 && !_wcsnicmp(equals + 1, L"Allow", value_length))
                hr = INetFwRule_put_Action(rule, NET_FW_ACTION_ALLOW);
            else if (value_length == 5 && !_wcsnicmp(equals + 1, L"Block", value_length))
                hr = INetFwRule_put_Action(rule, NET_FW_ACTION_BLOCK);
            else
                hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
        else if (!_wcsicmp(field, L"Dir"))
        {
            if (value_length == 2 && !_wcsnicmp(equals + 1, L"In", value_length))
                hr = INetFwRule_put_Direction(rule, NET_FW_RULE_DIR_IN);
            else if (value_length == 3 && !_wcsnicmp(equals + 1, L"Out", value_length))
                hr = INetFwRule_put_Direction(rule, NET_FW_RULE_DIR_OUT);
            else
                hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
        else if (!_wcsicmp(field, L"Active"))
        {
            if (value_length == 4 && !_wcsnicmp(equals + 1, L"TRUE", value_length))
                hr = INetFwRule_put_Enabled(rule, VARIANT_TRUE);
            else if (value_length == 5 && !_wcsnicmp(equals + 1, L"FALSE", value_length))
                hr = INetFwRule_put_Enabled(rule, VARIANT_FALSE);
            else
                hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
        else if (!_wcsicmp(field, L"Protocol"))
        {
            UINT32 protocol;

            if (fw_rule_parse_number(equals + 1, value_length, 256, &protocol))
                hr = INetFwRule_put_Protocol(rule, protocol);
            else
                hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
        else if (!_wcsicmp(field, L"Profile"))
        {
            if (value_length == 6 && !_wcsnicmp(equals + 1, L"Domain", value_length))
                profiles |= NET_FW_PROFILE2_DOMAIN;
            else if (value_length == 7 && !_wcsnicmp(equals + 1, L"Private", value_length))
                profiles |= NET_FW_PROFILE2_PRIVATE;
            else if (value_length == 6 && !_wcsnicmp(equals + 1, L"Public", value_length))
                profiles |= NET_FW_PROFILE2_PUBLIC;
            else
                hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            have_profiles = TRUE;
        }
        else if (!_wcsicmp(field, L"LPort") || !_wcsicmp(field, L"LPort2_10") ||
                 !_wcsicmp(field, L"RPort") || !_wcsicmp(field, L"RPort2_10") ||
                 !_wcsicmp(field, L"LA4") || !_wcsicmp(field, L"RA4") ||
                 !_wcsicmp(field, L"App") || !_wcsicmp(field, L"Desc") ||
                 !_wcsicmp(field, L"EmbedCtxt") || !_wcsicmp(field, L"Svc"))
        {
            BSTR value = SysAllocStringLen(equals + 1, value_length);
            if (!value)
                hr = E_OUTOFMEMORY;
            else if (!_wcsicmp(field, L"LPort") || !_wcsicmp(field, L"LPort2_10"))
                hr = INetFwRule_put_LocalPorts(rule, value);
            else if (!_wcsicmp(field, L"RPort") || !_wcsicmp(field, L"RPort2_10"))
                hr = INetFwRule_put_RemotePorts(rule, value);
            else if (!_wcsicmp(field, L"LA4"))
                hr = INetFwRule_put_LocalAddresses(rule, value);
            else if (!_wcsicmp(field, L"RA4"))
                hr = INetFwRule_put_RemoteAddresses(rule, value);
            else if (!_wcsicmp(field, L"App"))
                hr = INetFwRule_put_ApplicationName(rule, value);
            else if (!_wcsicmp(field, L"Desc"))
                hr = INetFwRule_put_Description(rule, value);
            else if (!_wcsicmp(field, L"Svc"))
                hr = INetFwRule_put_ServiceName(rule, value);
            else
                hr = INetFwRule_put_Grouping(rule, value);
            SysFreeString(value);
        }
        else if (_wcsicmp(field, L"Name") && _wcsicmp(field, L"Svc") &&
                 _wcsicmp(field, L"EmbedCtxt") && _wcsicmp(field, L"v2.10"))
        {
            hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
        }

        free(field);
        if (FAILED(hr)) return hr;
        position = end + 1;
    }

    if (have_profiles)
        return INetFwRule_put_Profiles(rule, profiles);
    return S_OK;
}

static HRESULT WINAPI netfw_rules_QueryInterface(
    INetFwRules *iface,
    REFIID riid,
    void **object)
{
    fw_rules *This = impl_from_INetFwRules( iface );

    TRACE("%p %s %p\n", This, debugstr_guid( riid ), object );

    if ( IsEqualGUID( riid, &IID_INetFwRules ) ||
         IsEqualGUID( riid, &IID_IDispatch ) ||
         IsEqualGUID( riid, &IID_IUnknown ) )
    {
        *object = iface;
    }
    else
    {
        FIXME("interface %s not implemented\n", debugstr_guid(riid));
        return E_NOINTERFACE;
    }
    INetFwRules_AddRef( iface );
    return S_OK;
}

static ULONG WINAPI netfw_rules_AddRef(
    INetFwRules *iface )
{
    fw_rules *This = impl_from_INetFwRules( iface );
    return InterlockedIncrement( &This->refs );
}

static ULONG WINAPI netfw_rules_Release(
    INetFwRules *iface )
{
    fw_rules *This = impl_from_INetFwRules( iface );
    LONG refs = InterlockedDecrement( &This->refs );
    if (!refs)
    {
        TRACE("destroying %p\n", This);
        free( This );
    }
    return refs;
}

static HRESULT WINAPI netfw_rules_GetTypeInfoCount(
    INetFwRules *iface,
    UINT *pctinfo )
{
    fw_rules *This = impl_from_INetFwRules( iface );

    TRACE("%p %p\n", This, pctinfo);
    *pctinfo = 1;
    return S_OK;
}

static HRESULT WINAPI netfw_rules_GetTypeInfo(
    INetFwRules *iface,
    UINT iTInfo,
    LCID lcid,
    ITypeInfo **ppTInfo)
{
    fw_rules *This = impl_from_INetFwRules( iface );

    TRACE("%p %u %lu %p\n", This, iTInfo, lcid, ppTInfo);
    return get_typeinfo( INetFwRules_tid, ppTInfo );
}

static HRESULT WINAPI netfw_rules_GetIDsOfNames(
    INetFwRules *iface,
    REFIID riid,
    LPOLESTR *rgszNames,
    UINT cNames,
    LCID lcid,
    DISPID *rgDispId)
{
    fw_rules *This = impl_from_INetFwRules( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %s %p %u %lu %p\n", This, debugstr_guid(riid), rgszNames, cNames, lcid, rgDispId);

    hr = get_typeinfo( INetFwRules_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_GetIDsOfNames( typeinfo, rgszNames, cNames, rgDispId );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI netfw_rules_Invoke(
    INetFwRules *iface,
    DISPID dispIdMember,
    REFIID riid,
    LCID lcid,
    WORD wFlags,
    DISPPARAMS *pDispParams,
    VARIANT *pVarResult,
    EXCEPINFO *pExcepInfo,
    UINT *puArgErr)
{
    fw_rules *This = impl_from_INetFwRules( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %ld %s %ld %d %p %p %p %p\n", This, dispIdMember, debugstr_guid(riid),
          lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);

    hr = get_typeinfo( INetFwRules_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_Invoke( typeinfo, &This->INetFwRules_iface, dispIdMember,
                               wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI netfw_rules_get_Count(
    INetFwRules *iface,
    LONG *count)
{
    HKEY key;
    DWORD value_count;
    LONG error;
    HRESULT hr;

    if (!count) return E_POINTER;
    *count = 0;

    hr = fw_rules_open_registry(FALSE, KEY_QUERY_VALUE, &key);
    if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
        return S_OK;
    if (FAILED(hr)) return hr;

    error = RegQueryInfoKeyW(key, NULL, NULL, NULL, NULL, NULL, NULL,
                             &value_count, NULL, NULL, NULL, NULL);
    RegCloseKey(key);
    if (error != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(error);
    if (value_count > LONG_MAX)
        return HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
    *count = value_count;
    return S_OK;
}

static HRESULT WINAPI netfw_rules_Add(
    INetFwRules *iface,
    INetFwRule *rule)
{
    fw_rule rule_data;
    WCHAR serialized[FIREWALL_RULE_MAX_CHARS];
    HKEY key;
    DWORD size = sizeof(WCHAR);
    LONG error;
    HRESULT hr;

    if (!rule) return E_POINTER;
    ZeroMemory(&rule_data, sizeof(rule_data));
    VariantInit(&rule_data.interfaces);
    hr = INetFwRule_get_Name(rule, &rule_data.name);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Description(rule, &rule_data.description);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_ApplicationName(rule, &rule_data.application);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_ServiceName(rule, &rule_data.service);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Protocol(rule, &rule_data.protocol);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_LocalPorts(rule, &rule_data.local_ports);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_RemotePorts(rule, &rule_data.remote_ports);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_LocalAddresses(rule, &rule_data.local_addresses);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_RemoteAddresses(rule, &rule_data.remote_addresses);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_IcmpTypesAndCodes(rule, &rule_data.icmp_types);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Direction(rule, &rule_data.direction);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Interfaces(rule, &rule_data.interfaces);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_InterfaceTypes(rule, &rule_data.interface_types);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Enabled(rule, &rule_data.enabled);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Grouping(rule, &rule_data.grouping);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Profiles(rule, &rule_data.profiles);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_EdgeTraversal(rule, &rule_data.edge_traversal);
    if (SUCCEEDED(hr)) hr = INetFwRule_get_Action(rule, &rule_data.action);
    if (FAILED(hr)) goto Exit;

    rule_data.has_direction = TRUE;
    rule_data.has_action = TRUE;
    rule_data.has_protocol = TRUE;
    rule_data.has_profiles = TRUE;
    if (rule->lpVtbl == &fw_rule_vtbl)
    {
        fw_rule *source = impl_from_INetFwRule(rule);
        rule_data.has_direction = source->has_direction;
        rule_data.has_action = source->has_action;
        rule_data.has_protocol = source->has_protocol;
        rule_data.has_profiles = source->has_profiles;
    }

    hr = fw_rule_serialize(&rule_data, serialized, ARRAYSIZE(serialized));
    if (FAILED(hr)) goto Exit;
    hr = fw_rules_open_registry(TRUE, KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
    if (FAILED(hr)) goto Exit;

    error = RegQueryValueExW(key, rule_data.name, NULL, NULL, NULL, &size);
    if (error == ERROR_SUCCESS)
        hr = HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
    else if (error != ERROR_FILE_NOT_FOUND)
        hr = HRESULT_FROM_WIN32(error);
    else
    {
        error = RegSetValueExW(key, rule_data.name, 0, REG_SZ,
                               (const BYTE *)serialized,
                               ((DWORD)wcslen(serialized) + 1) * sizeof(WCHAR));
        hr = error == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(error);
    }
    RegCloseKey(key);

Exit:
    SysFreeString(rule_data.name);
    SysFreeString(rule_data.description);
    SysFreeString(rule_data.application);
    SysFreeString(rule_data.service);
    SysFreeString(rule_data.local_ports);
    SysFreeString(rule_data.remote_ports);
    SysFreeString(rule_data.local_addresses);
    SysFreeString(rule_data.remote_addresses);
    SysFreeString(rule_data.icmp_types);
    SysFreeString(rule_data.interface_types);
    SysFreeString(rule_data.grouping);
    VariantClear(&rule_data.interfaces);
    return hr;
}

static HRESULT WINAPI netfw_rules_Remove(
    INetFwRules *iface,
    BSTR name)
{
    HKEY key;
    LONG error;
    HRESULT hr;

    if (!fw_rule_name_supported(name)) return E_INVALIDARG;
    hr = fw_rules_open_registry(FALSE, KEY_SET_VALUE, &key);
    if (FAILED(hr)) return hr;
    error = RegDeleteValueW(key, name);
    RegCloseKey(key);
    return error == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(error);
}

static HRESULT WINAPI netfw_rules_Item(
    INetFwRules *iface,
    BSTR name,
    INetFwRule **rule)
{
    HKEY key;
    DWORD type, size;
    BYTE *data = NULL;
    HRESULT hr;
    LONG error;
    INetFwRule *new_rule = NULL;

    if (!rule) return E_POINTER;
    *rule = NULL;
    if (!fw_rule_name_supported(name)) return E_INVALIDARG;

    hr = fw_rules_open_registry(FALSE, KEY_QUERY_VALUE, &key);
    if (FAILED(hr)) return hr;
    error = RegQueryValueExW(key, name, NULL, &type, NULL, &size);
    if (error != ERROR_SUCCESS)
    {
        RegCloseKey(key);
        return HRESULT_FROM_WIN32(error);
    }
    if (type != REG_SZ || size < sizeof(WCHAR) || size % sizeof(WCHAR) != 0 ||
        size > FIREWALL_RULE_MAX_CHARS * sizeof(WCHAR))
    {
        RegCloseKey(key);
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }
    data = malloc(size);
    if (!data)
    {
        RegCloseKey(key);
        return E_OUTOFMEMORY;
    }
    error = RegQueryValueExW(key, name, NULL, &type, data, &size);
    RegCloseKey(key);
    if (error != ERROR_SUCCESS)
    {
        free(data);
        return HRESULT_FROM_WIN32(error);
    }
    if (((WCHAR *)data)[size / sizeof(WCHAR) - 1] != 0 ||
        wcslen((WCHAR *)data) != size / sizeof(WCHAR) - 1)
    {
        free(data);
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }

    hr = NetFwRule_create(NULL, (void **)&new_rule);
    if (SUCCEEDED(hr))
        hr = INetFwRule_put_Name(new_rule, name);
    if (SUCCEEDED(hr))
        hr = fw_rule_parse_value(new_rule, (PCWSTR)data);
    free(data);
    if (FAILED(hr))
    {
        if (new_rule) INetFwRule_Release(new_rule);
        return hr;
    }
    *rule = new_rule;
    return S_OK;
}

static HRESULT NewEnum_create(fw_rules *rules, IUnknown **obj);

typedef struct
{
    IEnumVARIANT IEnumVARIANT_iface;
    LONG ref, pos;
    fw_rules *rules;
} EnumVARIANT;

static inline EnumVARIANT *impl_from_IEnumVARIANT(IEnumVARIANT *iface)
{
    return CONTAINING_RECORD(iface, EnumVARIANT, IEnumVARIANT_iface);
}

static HRESULT WINAPI enumvar_QueryInterface(IEnumVARIANT *iface, REFIID riid, void **obj)
{
    if (!riid || !obj) return E_INVALIDARG;

    TRACE("%p,%s,%p\n", iface, debugstr_guid(riid), obj);

    if (IsEqualGUID(riid, &IID_IEnumVARIANT) ||
        IsEqualGUID(riid, &IID_IUnknown))
    {
        IEnumVARIANT_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI enumvar_AddRef(IEnumVARIANT *iface)
{
    EnumVARIANT *enumvar = impl_from_IEnumVARIANT(iface);
    return InterlockedIncrement(&enumvar->ref);
}

static ULONG WINAPI enumvar_Release(IEnumVARIANT *iface)
{
    EnumVARIANT *enumvar = impl_from_IEnumVARIANT(iface);
    LONG ref = InterlockedDecrement(&enumvar->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);
        INetFwRules_Release(&enumvar->rules->INetFwRules_iface);
        free(enumvar);
    }

    return ref;
}

static HRESULT fw_rules_name_at(fw_rules *rules, ULONG index, BSTR *name)
{
    HKEY key;
    DWORD value_count, max_name_length, name_length;
    WCHAR *buffer;
    LONG error;
    HRESULT hr;

    *name = NULL;
    hr = fw_rules_open_registry(FALSE, KEY_QUERY_VALUE, &key);
    if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
        return S_FALSE;
    if (FAILED(hr)) return hr;

    error = RegQueryInfoKeyW(key, NULL, NULL, NULL, NULL, NULL, NULL,
                             &value_count, &max_name_length, NULL, NULL, NULL);
    if (error != ERROR_SUCCESS)
    {
        RegCloseKey(key);
        return HRESULT_FROM_WIN32(error);
    }
    if (index >= value_count)
    {
        RegCloseKey(key);
        return S_FALSE;
    }
    buffer = malloc(((SIZE_T)max_name_length + 1) * sizeof(WCHAR));
    if (!buffer)
    {
        RegCloseKey(key);
        return E_OUTOFMEMORY;
    }
    name_length = max_name_length + 1;
    error = RegEnumValueW(key, index, buffer, &name_length, NULL, NULL, NULL, NULL);
    RegCloseKey(key);
    if (error != ERROR_SUCCESS)
    {
        free(buffer);
        return HRESULT_FROM_WIN32(error);
    }
    *name = SysAllocStringLen(buffer, name_length);
    free(buffer);
    return *name ? S_OK : E_OUTOFMEMORY;
}

static HRESULT WINAPI enumvar_Next(IEnumVARIANT *iface, ULONG celt, VARIANT *var, ULONG *fetched)
{
    EnumVARIANT *enumvar = impl_from_IEnumVARIANT(iface);
    ULONG count = 0;
    HRESULT hr;

    if (!var || (!fetched && celt != 1))
        return E_POINTER;
    if (fetched) *fetched = 0;

    while (count < celt)
    {
        BSTR name;
        INetFwRule *rule;
        IDispatch *dispatch;

        hr = fw_rules_name_at(enumvar->rules, enumvar->pos, &name);
        if (hr == S_FALSE)
            break;
        if (FAILED(hr))
            return hr;
        hr = INetFwRules_Item(&enumvar->rules->INetFwRules_iface, name, &rule);
        SysFreeString(name);
        if (FAILED(hr))
            return hr;
        hr = INetFwRule_QueryInterface(rule, &IID_IDispatch, (void **)&dispatch);
        INetFwRule_Release(rule);
        if (FAILED(hr))
            return hr;

        VariantInit(&var[count]);
        V_VT(&var[count]) = VT_DISPATCH;
        V_DISPATCH(&var[count]) = dispatch;
        enumvar->pos++;
        count++;
    }
    if (fetched) *fetched = count;
    return count == celt ? S_OK : S_FALSE;
}

static HRESULT WINAPI enumvar_Skip(IEnumVARIANT *iface, ULONG celt)
{
    EnumVARIANT *enumvar = impl_from_IEnumVARIANT(iface);
    LONG total;
    HRESULT hr;

    hr = INetFwRules_get_Count(&enumvar->rules->INetFwRules_iface, &total);
    if (FAILED(hr)) return hr;
    if (enumvar->pos >= total)
        return celt == 0 ? S_OK : S_FALSE;
    if (celt > (ULONG)(total - enumvar->pos))
    {
        enumvar->pos = total;
        return S_FALSE;
    }
    enumvar->pos += (LONG)celt;
    return S_OK;
}

static HRESULT WINAPI enumvar_Reset(IEnumVARIANT *iface)
{
    EnumVARIANT *enumvar = impl_from_IEnumVARIANT(iface);

    TRACE("%p\n", iface);

    enumvar->pos = 0;

    return S_OK;
}

static HRESULT WINAPI enumvar_Clone(IEnumVARIANT *iface, IEnumVARIANT **penum)
{
    EnumVARIANT *enumvar = impl_from_IEnumVARIANT(iface);
    IUnknown *clone;
    HRESULT hr;

    if (!penum) return E_POINTER;
    *penum = NULL;
    hr = NewEnum_create(enumvar->rules, &clone);
    if (SUCCEEDED(hr))
    {
        EnumVARIANT *copy = impl_from_IEnumVARIANT((IEnumVARIANT *)clone);
        copy->pos = enumvar->pos;
        *penum = (IEnumVARIANT *)clone;
    }
    return hr;
}

static const struct IEnumVARIANTVtbl EnumVARIANT_vtbl =
{
    enumvar_QueryInterface,
    enumvar_AddRef,
    enumvar_Release,
    enumvar_Next,
    enumvar_Skip,
    enumvar_Reset,
    enumvar_Clone
};

static HRESULT NewEnum_create(fw_rules *rules, IUnknown **obj)
{
    EnumVARIANT *enumvar;

    enumvar = malloc(sizeof(*enumvar));
    if (!enumvar) return E_OUTOFMEMORY;

    enumvar->IEnumVARIANT_iface.lpVtbl = &EnumVARIANT_vtbl;
    enumvar->ref = 1;
    enumvar->pos = 0;
    enumvar->rules = rules;
    INetFwRules_AddRef(&rules->INetFwRules_iface);

    *obj = (IUnknown *)&enumvar->IEnumVARIANT_iface;

    TRACE("created %p\n", *obj);

    return S_OK;
}

static HRESULT WINAPI netfw_rules_get__NewEnum(
    INetFwRules *iface,
    IUnknown **newEnum)
{
    fw_rules *This = impl_from_INetFwRules( iface );

    TRACE("%p, %p\n", This, newEnum);

    if (!newEnum) return E_POINTER;

    return NewEnum_create(This, newEnum);
}

static const struct INetFwRulesVtbl fw_rules_vtbl =
{
    netfw_rules_QueryInterface,
    netfw_rules_AddRef,
    netfw_rules_Release,
    netfw_rules_GetTypeInfoCount,
    netfw_rules_GetTypeInfo,
    netfw_rules_GetIDsOfNames,
    netfw_rules_Invoke,
    netfw_rules_get_Count,
    netfw_rules_Add,
    netfw_rules_Remove,
    netfw_rules_Item,
    netfw_rules_get__NewEnum
};

static HRESULT create_INetFwRules(INetFwRules **object)
{
    fw_rules *rules;

    TRACE("(%p)\n", object);

    rules = malloc( sizeof(*rules) );
    if (!rules) return E_OUTOFMEMORY;

    rules->INetFwRules_iface.lpVtbl = &fw_rules_vtbl;
    rules->refs = 1;

    *object = &rules->INetFwRules_iface;

    TRACE("returning iface %p\n", *object);
    return S_OK;
}

static ULONG WINAPI fw_policy_AddRef(
    INetFwPolicy *iface )
{
    fw_policy *fw_policy = impl_from_INetFwPolicy( iface );
    return InterlockedIncrement( &fw_policy->refs );
}

static ULONG WINAPI fw_policy_Release(
    INetFwPolicy *iface )
{
    fw_policy *fw_policy = impl_from_INetFwPolicy( iface );
    LONG refs = InterlockedDecrement( &fw_policy->refs );
    if (!refs)
    {
        TRACE("destroying %p\n", fw_policy);
        free( fw_policy );
    }
    return refs;
}

static HRESULT WINAPI fw_policy_QueryInterface(
    INetFwPolicy *iface,
    REFIID riid,
    void **ppvObject )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );

    TRACE("%p %s %p\n", This, debugstr_guid( riid ), ppvObject );

    if ( IsEqualGUID( riid, &IID_INetFwPolicy ) ||
         IsEqualGUID( riid, &IID_IDispatch ) ||
         IsEqualGUID( riid, &IID_IUnknown ) )
    {
        *ppvObject = iface;
    }
    else
    {
        FIXME("interface %s not implemented\n", debugstr_guid(riid));
        return E_NOINTERFACE;
    }
    INetFwPolicy_AddRef( iface );
    return S_OK;
}

static HRESULT WINAPI fw_policy_GetTypeInfoCount(
    INetFwPolicy *iface,
    UINT *pctinfo )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );

    TRACE("%p %p\n", This, pctinfo);
    *pctinfo = 1;
    return S_OK;
}

static HRESULT WINAPI fw_policy_GetTypeInfo(
    INetFwPolicy *iface,
    UINT iTInfo,
    LCID lcid,
    ITypeInfo **ppTInfo )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );

    TRACE("%p %u %lu %p\n", This, iTInfo, lcid, ppTInfo);
    return get_typeinfo( INetFwPolicy_tid, ppTInfo );
}

static HRESULT WINAPI fw_policy_GetIDsOfNames(
    INetFwPolicy *iface,
    REFIID riid,
    LPOLESTR *rgszNames,
    UINT cNames,
    LCID lcid,
    DISPID *rgDispId )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %s %p %u %lu %p\n", This, debugstr_guid(riid), rgszNames, cNames, lcid, rgDispId);

    hr = get_typeinfo( INetFwPolicy_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_GetIDsOfNames( typeinfo, rgszNames, cNames, rgDispId );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI fw_policy_Invoke(
    INetFwPolicy *iface,
    DISPID dispIdMember,
    REFIID riid,
    LCID lcid,
    WORD wFlags,
    DISPPARAMS *pDispParams,
    VARIANT *pVarResult,
    EXCEPINFO *pExcepInfo,
    UINT *puArgErr )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %ld %s %ld %d %p %p %p %p\n", This, dispIdMember, debugstr_guid(riid),
          lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);

    hr = get_typeinfo( INetFwPolicy_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_Invoke( typeinfo, &This->INetFwPolicy_iface, dispIdMember,
                               wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI fw_policy_get_CurrentProfile(
    INetFwPolicy *iface,
    INetFwProfile **profile )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );

    TRACE("%p, %p\n", This, profile);
    return NetFwProfile_create( NULL, (void **)profile );
}

static HRESULT WINAPI fw_policy_GetProfileByType(
    INetFwPolicy *iface,
    NET_FW_PROFILE_TYPE profileType,
    INetFwProfile **profile )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );

    FIXME("%p, %u, %p\n", This, profileType, profile);
    return E_NOTIMPL;
}

static const struct INetFwPolicyVtbl fw_policy_vtbl =
{
    fw_policy_QueryInterface,
    fw_policy_AddRef,
    fw_policy_Release,
    fw_policy_GetTypeInfoCount,
    fw_policy_GetTypeInfo,
    fw_policy_GetIDsOfNames,
    fw_policy_Invoke,
    fw_policy_get_CurrentProfile,
    fw_policy_GetProfileByType
};

HRESULT NetFwPolicy_create( IUnknown *pUnkOuter, LPVOID *ppObj )
{
    fw_policy *fp;

    TRACE("(%p,%p)\n", pUnkOuter, ppObj);

    fp = malloc( sizeof(*fp) );
    if (!fp) return E_OUTOFMEMORY;

    fp->INetFwPolicy_iface.lpVtbl = &fw_policy_vtbl;
    fp->refs = 1;

    *ppObj = &fp->INetFwPolicy_iface;

    TRACE("returning iface %p\n", *ppObj);
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_QueryInterface(INetFwPolicy2 *iface, REFIID riid, void **out)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    TRACE("%p %s %p\n", This, debugstr_guid( riid ), out );

    if ( IsEqualGUID( riid, &IID_INetFwPolicy2 ) ||
         IsEqualGUID( riid, &IID_IDispatch ) ||
         IsEqualGUID( riid, &IID_IUnknown ) )
    {
        *out = iface;
    }
    else if( IsEqualGUID( riid, &IID_INetFwRules ) )
    {
        TRACE("INetFwRules not supported\n");
        return E_NOINTERFACE;
    }
    else
    {
        FIXME("interface %s not implemented\n", debugstr_guid(riid));
        return E_NOINTERFACE;
    }
    INetFwPolicy2_AddRef( iface );
    return S_OK;
}

static ULONG WINAPI fwpolicy2_AddRef(INetFwPolicy2 *iface)
{
    fw_policy2 *fw_policy = impl_from_INetFwPolicy2( iface );
    return InterlockedIncrement( &fw_policy->refs );
}

static ULONG WINAPI fwpolicy2_Release(INetFwPolicy2 *iface)
{
    fw_policy2 *fw_policy = impl_from_INetFwPolicy2( iface );
    LONG refs = InterlockedDecrement( &fw_policy->refs );
    if (!refs)
    {
        INetFwRules_Release(fw_policy->fw_policy2_rules);
        TRACE("destroying %p\n", fw_policy);
        free( fw_policy );
    }
    return refs;
}

static HRESULT WINAPI fwpolicy2_GetTypeInfoCount(INetFwPolicy2 *iface, UINT *pctinfo)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    TRACE("%p %p\n", This, pctinfo);
    *pctinfo = 1;
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_GetTypeInfo(INetFwPolicy2 *iface, UINT iTInfo, LCID lcid, ITypeInfo **info)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    TRACE("%p %u %lu %p\n", This, iTInfo, lcid, info);
    return get_typeinfo( INetFwPolicy2_tid, info );
}

static HRESULT WINAPI fwpolicy2_GetIDsOfNames(INetFwPolicy2 *iface, REFIID riid, LPOLESTR *rgszNames,
                        UINT cNames, LCID lcid, DISPID *rgDispId)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %s %p %u %lu %p\n", This, debugstr_guid(riid), rgszNames, cNames, lcid, rgDispId);

    hr = get_typeinfo( INetFwPolicy2_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_GetIDsOfNames( typeinfo, rgszNames, cNames, rgDispId );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI fwpolicy2_Invoke(INetFwPolicy2 *iface, DISPID dispIdMember, REFIID riid, LCID lcid,
                WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %ld %s %ld %d %p %p %p %p\n", This, dispIdMember, debugstr_guid(riid),
          lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);

    hr = get_typeinfo( INetFwPolicy2_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_Invoke( typeinfo, &This->INetFwPolicy2_iface, dispIdMember,
                               wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI fwpolicy2_get_CurrentProfileTypes(INetFwPolicy2 *iface, LONG *profile)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %p\n", This, profile);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_FirewallEnabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL *enabled)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %p\n", This, profileType, enabled);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_put_FirewallEnabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL enabled)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %d\n", This, profileType, enabled);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_ExcludedInterfaces(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT *interfaces)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %p\n", This, profileType, interfaces);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_put_ExcludedInterfaces(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT interfaces)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );
    FIXME("%p %d\n", This, profileType);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_BlockAllInboundTraffic(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL *block)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %p\n", This, profileType, block);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_put_BlockAllInboundTraffic(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL block)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %d\n", This, profileType, block);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_NotificationsDisabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL *disabled)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %p\n", This, profileType, disabled);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_put_NotificationsDisabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL disabled)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %d\n", This, profileType, disabled);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_UnicastResponsesToMulticastBroadcastDisabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL *disabled)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %p\n", This, profileType, disabled);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_put_UnicastResponsesToMulticastBroadcastDisabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL disabled)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %d\n", This, profileType, disabled);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_Rules(INetFwPolicy2 *iface, INetFwRules **rules)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    TRACE("%p %p\n", This, rules);

    if(!rules)
        return E_POINTER;

    *rules = This->fw_policy2_rules;
    INetFwRules_AddRef(This->fw_policy2_rules);

    return S_OK;
}

#ifdef __REACTOS__
typedef struct fw_service_restriction
{
    INetFwServiceRestriction INetFwServiceRestriction_iface;
    INetFwRules *rules;
    LONG refs;
} fw_service_restriction;

static inline fw_service_restriction *impl_from_INetFwServiceRestriction( INetFwServiceRestriction *iface )
{
    return CONTAINING_RECORD(iface, fw_service_restriction, INetFwServiceRestriction_iface);
}

static HRESULT WINAPI fw_service_restriction_QueryInterface( INetFwServiceRestriction *iface, REFIID riid, void **object )
{
    fw_service_restriction *This = impl_from_INetFwServiceRestriction( iface );

    TRACE("%p %s %p\n", This, debugstr_guid( riid ), object );

    if ( IsEqualGUID( riid, &IID_INetFwServiceRestriction ) ||
         IsEqualGUID( riid, &IID_IDispatch ) ||
         IsEqualGUID( riid, &IID_IUnknown ) )
    {
        *object = iface;
        INetFwServiceRestriction_AddRef( iface );
        return S_OK;
    }

    FIXME("interface %s not implemented\n", debugstr_guid(riid));
    *object = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI fw_service_restriction_AddRef( INetFwServiceRestriction *iface )
{
    fw_service_restriction *This = impl_from_INetFwServiceRestriction( iface );
    return InterlockedIncrement( &This->refs );
}

static ULONG WINAPI fw_service_restriction_Release( INetFwServiceRestriction *iface )
{
    fw_service_restriction *This = impl_from_INetFwServiceRestriction( iface );
    LONG refs = InterlockedDecrement( &This->refs );

    if (!refs)
    {
        TRACE("destroying %p\n", This);
        INetFwRules_Release( This->rules );
        free( This );
    }
    return refs;
}

static HRESULT WINAPI fw_service_restriction_GetTypeInfoCount( INetFwServiceRestriction *iface, UINT *pctinfo )
{
    fw_service_restriction *This = impl_from_INetFwServiceRestriction( iface );

    FIXME("%p %p\n", This, pctinfo);
    return E_NOTIMPL;
}

static HRESULT WINAPI fw_service_restriction_GetTypeInfo( INetFwServiceRestriction *iface, UINT iTInfo, LCID lcid,
                                                          ITypeInfo **ppTInfo )
{
    fw_service_restriction *This = impl_from_INetFwServiceRestriction( iface );

    FIXME("%p %u %lu %p\n", This, iTInfo, lcid, ppTInfo);
    return E_NOTIMPL;
}

static HRESULT WINAPI fw_service_restriction_GetIDsOfNames( INetFwServiceRestriction *iface, REFIID riid,
                                                            LPOLESTR *rgszNames, UINT cNames, LCID lcid,
                                                            DISPID *rgDispId )
{
    fw_service_restriction *This = impl_from_INetFwServiceRestriction( iface );

    FIXME("%p %s %p %u %lu %p\n", This, debugstr_guid(riid), rgszNames, cNames, lcid, rgDispId);
    return E_NOTIMPL;
}

static HRESULT WINAPI fw_service_restriction_Invoke( INetFwServiceRestriction *iface, DISPID dispIdMember,
                                                     REFIID riid, LCID lcid, WORD wFlags,
                                                     DISPPARAMS *pDispParams, VARIANT *pVarResult,
                                                     EXCEPINFO *pExcepInfo, UINT *puArgErr )
{
    fw_service_restriction *This = impl_from_INetFwServiceRestriction( iface );

    FIXME("%p %ld %s %ld %d %p %p %p %p\n", This, dispIdMember, debugstr_guid(riid),
          lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);
    return E_NOTIMPL;
}

static HRESULT WINAPI fw_service_restriction_RestrictService( INetFwServiceRestriction *iface, BSTR serviceName,
                                                              BSTR appName, VARIANT_BOOL restrictService,
                                                              VARIANT_BOOL serviceSidRestricted )
{
    fw_service_restriction *This = impl_from_INetFwServiceRestriction( iface );

    FIXME("%p %s %s %d %d\n", This, debugstr_w(serviceName), debugstr_w(appName), restrictService,
          serviceSidRestricted);
    return E_NOTIMPL;
}

static HRESULT WINAPI fw_service_restriction_ServiceRestricted( INetFwServiceRestriction *iface, BSTR serviceName,
                                                                BSTR appName, VARIANT_BOOL *serviceRestricted )
{
    fw_service_restriction *This = impl_from_INetFwServiceRestriction( iface );

    FIXME("%p %s %s %p\n", This, debugstr_w(serviceName), debugstr_w(appName), serviceRestricted);
    return E_NOTIMPL;
}

static HRESULT WINAPI fw_service_restriction_get_Rules( INetFwServiceRestriction *iface, INetFwRules **rules )
{
    fw_service_restriction *This = impl_from_INetFwServiceRestriction( iface );

    TRACE("%p %p\n", This, rules);

    if (!rules)
        return E_POINTER;

    *rules = This->rules;
    INetFwRules_AddRef( This->rules );
    return S_OK;
}

static const struct INetFwServiceRestrictionVtbl fw_service_restriction_vtbl =
{
    fw_service_restriction_QueryInterface,
    fw_service_restriction_AddRef,
    fw_service_restriction_Release,
    fw_service_restriction_GetTypeInfoCount,
    fw_service_restriction_GetTypeInfo,
    fw_service_restriction_GetIDsOfNames,
    fw_service_restriction_Invoke,
    fw_service_restriction_RestrictService,
    fw_service_restriction_ServiceRestricted,
    fw_service_restriction_get_Rules
};
#endif

static HRESULT WINAPI fwpolicy2_get_ServiceRestriction(INetFwPolicy2 *iface, INetFwServiceRestriction **ServiceRestriction)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );
#ifdef __REACTOS__
    fw_service_restriction *restriction;

    TRACE("%p %p\n", This, ServiceRestriction);

    if (!ServiceRestriction)
        return E_POINTER;

    if (!(restriction = malloc( sizeof(*restriction) )))
        return E_OUTOFMEMORY;

    if (FAILED(create_INetFwRules( &restriction->rules )))
    {
        free( restriction );
        return E_OUTOFMEMORY;
    }

    restriction->INetFwServiceRestriction_iface.lpVtbl = &fw_service_restriction_vtbl;
    restriction->refs = 1;
    *ServiceRestriction = &restriction->INetFwServiceRestriction_iface;
    return S_OK;
#else

    FIXME("%p %p\n", This, ServiceRestriction);
    return E_NOTIMPL;
#endif
}

static HRESULT WINAPI fwpolicy2_EnableRuleGroup(INetFwPolicy2 *iface, LONG bitmask, BSTR group, VARIANT_BOOL enable)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %ld %s %d\n", This, bitmask, debugstr_w(group), enable);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_IsRuleGroupEnabled(INetFwPolicy2 *iface, LONG bitmask, BSTR group, VARIANT_BOOL *enabled)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %ld %s %p\n", This, bitmask, debugstr_w(group), enabled);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_RestoreLocalFirewallDefaults(INetFwPolicy2 *iface)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p\n", This);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_DefaultInboundAction(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, NET_FW_ACTION *action)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %p\n", This, profileType, action);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_put_DefaultInboundAction(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, NET_FW_ACTION action)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %d\n", This, profileType, action);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_DefaultOutboundAction(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, NET_FW_ACTION *action)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %p\n", This, profileType, action);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_put_DefaultOutboundAction(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, NET_FW_ACTION action)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %d\n", This, profileType, action);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_IsRuleGroupCurrentlyEnabled(INetFwPolicy2 *iface, BSTR group, VARIANT_BOOL *enabled)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %s %p\n", This, debugstr_w(group), enabled);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_LocalPolicyModifyState(INetFwPolicy2 *iface, NET_FW_MODIFY_STATE *modifyState)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %p\n", This, modifyState);
    return E_NOTIMPL;
}

static const struct INetFwPolicy2Vtbl fw_policy2_vtbl =
{
    fwpolicy2_QueryInterface,
    fwpolicy2_AddRef,
    fwpolicy2_Release,
    fwpolicy2_GetTypeInfoCount,
    fwpolicy2_GetTypeInfo,
    fwpolicy2_GetIDsOfNames,
    fwpolicy2_Invoke,
    fwpolicy2_get_CurrentProfileTypes,
    fwpolicy2_get_FirewallEnabled,
    fwpolicy2_put_FirewallEnabled,
    fwpolicy2_get_ExcludedInterfaces,
    fwpolicy2_put_ExcludedInterfaces,
    fwpolicy2_get_BlockAllInboundTraffic,
    fwpolicy2_put_BlockAllInboundTraffic,
    fwpolicy2_get_NotificationsDisabled,
    fwpolicy2_put_NotificationsDisabled,
    fwpolicy2_get_UnicastResponsesToMulticastBroadcastDisabled,
    fwpolicy2_put_UnicastResponsesToMulticastBroadcastDisabled,
    fwpolicy2_get_Rules,
    fwpolicy2_get_ServiceRestriction,
    fwpolicy2_EnableRuleGroup,
    fwpolicy2_IsRuleGroupEnabled,
    fwpolicy2_RestoreLocalFirewallDefaults,
    fwpolicy2_get_DefaultInboundAction,
    fwpolicy2_put_DefaultInboundAction,
    fwpolicy2_get_DefaultOutboundAction,
    fwpolicy2_put_DefaultOutboundAction,
    fwpolicy2_get_IsRuleGroupCurrentlyEnabled,
    fwpolicy2_get_LocalPolicyModifyState
};

HRESULT NetFwPolicy2_create( IUnknown *outer, void **obj )
{
    fw_policy2 *fp;

    TRACE("(%p,%p)\n", outer, obj);

    fp = malloc( sizeof(*fp) );
    if (!fp) return E_OUTOFMEMORY;

    fp->INetFwPolicy2_iface.lpVtbl = &fw_policy2_vtbl;
    fp->refs = 1;

    *obj = &fp->INetFwPolicy2_iface;

    if (FAILED(create_INetFwRules(&fp->fw_policy2_rules)))
    {
        free( fp );
        return E_OUTOFMEMORY;
    }

    TRACE("returning iface %p\n", *obj);
    return S_OK;
}
