#### Parser Content
```Java
{
Name = azure-event-hub-network-security-group-event
  DataType = "network-connection"
  Conditions = ["""ext_category=NetworkSecurityGroupEvent""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
     """\WrequestClientApplication=(|({app}.+?))(\s+\w+=|\s*$)""",
    """category":"({activity}.*?[^\\])"""",
    """type":"({outcome}.*?[^\\])"""",
    """rule":"({ruleName}.*?[^\\])"""",
    """sourceIP":"({src_ip}.*?[^\\])"""",
    """destinationIP":"({dest_ip}.*?[^\\])"""",
    """ruleName":"({rule}.*?[^\\])"""",
    """direction":"({direction}.*?[^\\])"""",
  ]
}
```