#### Parser Content
```Java
{
Name = azure-event-hub-network-security-group-rule-counter
  DataType = "network-connection"
  Conditions = ["""ext_category=NetworkSecurityGroupRuleCounter""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
     """\WrequestClientApplication=(|({app}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """category":"({activity}.*?[^\\])"""",
    """type":"({outcome}.*?[^\\])"""",
    """rule":"({ruleName}.*?[^\\])"""",
    """primaryIPv4Address":"({src_ip}.*?[^\\])"""",
    """ruleName":"({rule}.*?[^\\])"""",
    """direction":"({direction}.*?[^\\])"""",
  ]
}
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```