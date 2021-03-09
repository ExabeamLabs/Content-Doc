#### Parser Content
```Java
{
Name = cef-slack-app-activity
  Vendor = Slack
  Product = Slack
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """destinationServiceName=Slack""", """|Skyformation|""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)\s+[\w.\-]+\s+Skyformation""",
    """\WdestinationServiceName=({app}Slack)""",
    """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
    """user":\{"id":"({user_id}[^"]+)","name":"({user_fullname}[^"]+)"""",
    """\Wsuser=(|({user_email}[^@]+@({email_domain}[^=]+?)))(\s+\w+=|\s*$)""",
    """action":"({activity}[^"]+)""",
    """\Wext_entity_file_title=(|({file_name}\w+(\.({file_ext}\w+))?))(\s+\w+=|\s*$)"""
    """src=({src_ip}[a-fA-F\d.:]+)""",
    """"entity":\{"[^"]+":"[^"]+","[^"]+":\{("[^"]+":"[^"]+",){2}"name":"({object}[^"]+)"""",
    """"domain":"({domain}[^"]+)"""",
  ]
}
```