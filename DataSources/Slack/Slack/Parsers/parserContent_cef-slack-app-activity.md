#### Parser Content
```Java
{
Name = cef-slack-app-activity
  Vendor = Slack
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """destinationServiceName=Slack""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)\s+({host}[\w.\-]+)\s+Skyformation""",
    """\WdestinationServiceName=({app}Slack)""",
    """\Wext_actor_user_name=(|({user_fullname}.+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(|({user_email}.+?))(\s+\w+=|\s*$)""",
    """\Wext_actor_user_id=(|({user_id}.+?))(\s+\w+=|\s*$)""",
    """\WflexString1=(|({activity}.+?))(\s+\w+=|\s*$)""",
    """\Wext_entity_file_title=(|({file_name}\w+(\.({file_ext}\w+))?))(\s+\w+=|\s*$)"""
    """\Wext_context_ip_address_=({src_ip}[a-fA-F\d.:]+)""",
    """"entity":.+?"name":"({object}[^"]+)""",
    """\Wext_context_location_domain=(|({domain}.+?))(\s+\w+=|\s*$)""",
  ]
}
```