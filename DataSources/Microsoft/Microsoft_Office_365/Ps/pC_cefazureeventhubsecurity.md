#### Parser Content
```Java
{
Name = cef-azure-event-hub-security
  DataType = "alert"
  Conditions = ["""CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""",""""category":"Security"""", """"eventName"""", """EventHub"""]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """compromisedEntity":"({user_upn}[^"]{1,2000})"""",
    """userName":"(({domain}[^\\"]{1,2000})\\+)?({user}[^"]{1,2000})"""",
    """clientIPAddress":"({src_ip}[^",]{1,2000})""",
    """severity":"({alert_severity}[^"]{1,2000})"""",
    """operationId":"({alert_id}[^"]{1,2000})"""",
    """category":"({azure_category}[^"]{1,2000})"""",
    """attackedResourceType":"({azure_resource_type}[^"]{1,2000})"""",
    """\Wext_properties_eventProperties_attackers_0_=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wext_properties_eventProperties_previousIPAddress=(|({last_known_ip}[^=]{1,2000}))(\s{1,100}\w+=|\s{0,100}$)""",
    """eventName":"({alert_type}[^"\\]{1,2000})\\*"""",
    """\Wext_properties_eventProperties_malwareName=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """resultDescription":"({alert_name}[^"\\]{1,2000})\\*"""",
    """detailDescription":"({additional_info}[^"\\]{1,2000})\\*"""",
  ]
}
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```