# Send AuthnRequest extensions and read raw attributes (BundID)

Some IdPs need more than a plain AuthnRequest, and put more into an assertion
than attribute values. BundID, the German federal citizen account, is the
example this guide uses:

- the AuthnRequest must carry an `akdb:AuthenticationRequest` in
  `<samlp:Extensions>`, naming the requested attributes and what BundID shows
  the person;
- each released `<saml:Attribute>` carries an `akdb:TrustLevel` XML
  attribute that says how well the value is verified.

Both mechanisms are generic and work through `SamlEngine`, per login. The
BundID specifics live in `fastapi_auth.saml.akdb`.

## Add extensions to one login

`create_authn_request(extensions=...)` takes a sequence of pysaml2
`ExtensionElement` objects or of builders with a `to_extension_element()`
method. They become the children of `<samlp:Extensions>`, in order, and the
request is signed with them included. Another call without `extensions`
sends none -- nothing is stored on the engine.

For any XML element, parse it from a string:

```python
from fastapi_auth import saml

hint = saml.extension_element_from_xml('<x:Hint xmlns:x="urn:example:hint" Level="2"/>')
request_id, redirect_url = await engine.create_authn_request(relay_state="/app", extensions=[hint])
```

Each element must be namespace-qualified and outside the SAML namespaces
(SAML 2.0 Core, section 3.2.1); otherwise `ValueError` is raised.
`extension_element_from_xml()` refuses DTDs and entity declarations.

## Build the BundID request

```python
from fastapi_auth import saml
from fastapi_auth.saml import akdb

bundid = akdb.AuthenticationRequest(
    requested_attributes=(
        akdb.RequestedAttribute(name=akdb.BPK2, required=True),
        akdb.RequestedAttribute(name="urn:oid:2.5.4.42"),  # given name
    ),
    display_information=akdb.DisplayInformation(
        organization_display_name="Example University",
        online_service_id="example-service-id",
    ),
    # Optional: switch login methods on or off; unset ones keep the IdP default.
    authn_methods=akdb.AuthnMethods(eid=True, eidas=True, benutzername=False),
)
level_4 = saml.RequestedAuthnContext(
    class_refs=("STORK-QAA-Level-4",),
    comparison="minimum",
    ranking=akdb.STORK_QAA_LEVELS,
)

request_id, redirect_url = await engine.create_authn_request(
    relay_state="/app", extensions=[bundid], requested_authn_context=level_4
)
```

This produces:

```xml
<samlp:Extensions>
  <akdb:AuthenticationRequest xmlns:akdb="https://www.akdb.de/request/2018/09" Version="2">
    <akdb:AuthnMethods>
      <akdb:Benutzername><akdb:Enabled>false</akdb:Enabled></akdb:Benutzername>
      <akdb:eID><akdb:Enabled>true</akdb:Enabled></akdb:eID>
      <akdb:eIDAS><akdb:Enabled>true</akdb:Enabled></akdb:eIDAS>
    </akdb:AuthnMethods>
    <akdb:RequestedAttributes>
      <akdb:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.25484.494450.3" RequiredAttribute="true"/>
      <akdb:RequestedAttribute Name="urn:oid:2.5.4.42" RequiredAttribute="false"/>
    </akdb:RequestedAttributes>
    <akdb:DisplayInformation>
      <classic-ui:Version xmlns:classic-ui="https://www.akdb.de/request/2018/09/classic-ui/v1">
        <classic-ui:OrganizationDisplayName>Example University</classic-ui:OrganizationDisplayName>
        <classic-ui:OnlineServiceId>example-service-id</classic-ui:OnlineServiceId>
      </classic-ui:Version>
    </akdb:DisplayInformation>
  </akdb:AuthenticationRequest>
</samlp:Extensions>
```

Element names, order and namespaces follow the public source of
[keycloak-extension-bundid](https://github.com/ba-itsys/keycloak-extension-bundid),
a BundID service provider in production use. The operator's integration
guide is only available after registration; check the values you send
against it, in particular the `OnlineServiceId` you are assigned and which
attributes your service may request.

## Read raw attributes and their XML attributes

`parse_response()` returns `(identity, in_response_to)`; the identity keeps
attribute values only. `parse_response_details()` validates exactly the same
way and also returns every `<saml:Attribute>` of the verified, decrypted
assertion:

```python
result = await engine.parse_response_details(
    saml_response,
    outstanding={request_id: "/app"},
    requested_authn_context=level_4,
)
identity = result.identity  # FederatedIdentity, as before
bpk2 = result.attribute(akdb.BPK2)  # by Name, else by FriendlyName
if bpk2 is not None:
    bpk2.values  # ("...",)
    bpk2.xml_attributes  # {"{https://www.akdb.de/request/2018/09}TrustLevel": "HOCH"}
    akdb.trust_level(bpk2)  # akdb.TrustLevel.HOCH
```

`SamlAttribute.xml_attributes` holds every XML attribute beyond `Name`,
`NameFormat` and `FriendlyName`, with namespaced keys in Clark notation
(`{namespace}local-name`). `xml_attribute("TrustLevel", namespace=...)` looks
one up.

`akdb.trust_level()` returns `UNTERGEORDNET`, `NORMAL`, `SUBSTANTIELL` or
`HOCH` -- ordered, so `level >= akdb.TrustLevel.SUBSTANTIELL` works -- and
`level.stork_level` gives the matching `STORK-QAA-Level-1` to `-4`. An absent
or unknown value is `None`, never a guess. Decide per attribute whether its
level is high enough before you treat the value as verified: on low levels,
values such as an academic title are entered by the person themselves.

The raw attributes are a per-login input. They are not part of
`FederatedIdentity` and therefore not stored in the session; evaluate them
where you call `parse_response_details()`.
