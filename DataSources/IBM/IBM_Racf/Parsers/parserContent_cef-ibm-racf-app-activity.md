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
    """CEF:([^\|]{0,2000}\|){4}({event_code}[^\|]{1,2000})\|({activity}[^\|]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=(|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WcategoryOutcome=(|/({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wshost=(|({src_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdhost=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuid=(|({user_id}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsproc=(Null|({process_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wfname=(|({object}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs1=(|({group}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs2=(Null|({terminal}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs3=(|({operation}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs4=(|(({src_domain}[^\\\/=]{1,2000})[\\\/]{1,2000})?({src_user}[^\\\/=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs5=(|({environment}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs6=(NONE|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString1=(|({manager_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString2=(|({manager}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString1Label=(|({identifier}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs6Label=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
  DupFields = [ "terminal->app" ]
}
```