#### Parser Content
```Java
{
Name = cef-azure-event-hub-security
  DataType = "alert"
  Conditions = ["""CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""",""""category":"Security"""", """"eventName"""", """EventHub"""]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """compromisedEntity":"({user_upn}[^"]+)"""",
    """userName":"(({domain}[^\\"]+)\\+)?({user}[^"]+)"""",
    """clientIPAddress":"({src_ip}[^",]+)""",
    """severity":"({alert_severity}[^"]+)"""",
    """operationId":"({alert_id}[^"]+)"""",
    """category":"({azure_category}[^"]+)"""",
    """attackedResourceType":"({azure_resource_type}[^"]+)"""",
    """\Wext_properties_eventProperties_attackers_0_=({src_ip}[a-fA-F\d.:]+)""",
    """\Wext_properties_eventProperties_previousIPAddress=(|({last_known_ip}[^=]+))(\s+\w+=|\s*$)""",
    """eventName":"({alert_type}[^"\\]+)\\*"""",
    """\Wext_properties_eventProperties_malwareName=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """resultDescription":"({alert_name}[^"\\]+)\\*"""",
    """detailDescription":"({additional_info}[^"\\]+)\\*"""",
  ]
}
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```