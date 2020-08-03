#### Parser Content
```Java
{
Name = cef-ibm-racf-app-activity
  Vendor = IBM
  Product = IBM Racf
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|IBM|Racf|""" ]
  Fields = [
    """CEF:([^\|]*\|){4}({event_code}[^\|]+)\|({activity}[^\|]+)""",
    """\Wrt=({time}\d+)""",
    """\Wdvc=(|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\WcategoryOutcome=(|/({outcome}.+?))(\s+\w+=|\s*$)""",
    """\Wshost=(|({src_host}.+?))(\s+\w+=|\s*$)""",
    """\Wdhost=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(|({user}.+?))(\s+\w+=|\s*$)""",
    """\Wsuid=(|({user_id}.+?))(\s+\w+=|\s*$)""",
    """\Wsproc=(Null|({process_name}.+?))(\s+\w+=|\s*$)""",
    """\Wfname=(|({object}.+?))(\s+\w+=|\s*$)""",
    """\Wcs1=(|({group}.+?))(\s+\w+=|\s*$)""",
    """\Wcs2=(Null|({terminal}.+?))(\s+\w+=|\s*$)""",
    """\Wcs3=(|({operation}.+?))(\s+\w+=|\s*$)""",
    """\Wcs4=(|(({src_domain}[^\\\/=]+)[\\\/]+)?({src_user}[^\\\/=]+?))(\s+\w+=|\s*$)""",
    """\Wcs5=(|({environment}.+?))(\s+\w+=|\s*$)""",
    """\Wcs6=(NONE|({additional_info}.+?))(\s+\w+=|\s*$)""",
    """\WflexString1=(|({manager_name}.+?))(\s+\w+=|\s*$)""",
    """\WflexString2=(|({manager}.+?))(\s+\w+=|\s*$)""",
    """\WflexString1Label=(|({identifier}.+?))(\s+\w+=|\s*$)""",
    """\Wcs6Label=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
  ]
  DupFields = [ "terminal->app" ]
}
```