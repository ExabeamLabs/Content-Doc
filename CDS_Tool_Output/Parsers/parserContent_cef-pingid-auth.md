#### Parser Content
```Java
{
Name = cef-pingid-auth
  Vendor = Ping Identity
  Product = PingID
  Lms = ArcSight
  DataType = "authentication-attempt"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Conditions= [ """CEF:""", """|GlobalAuth|SSAA|""", """responsetime=""" ]
  Fields=[
    """CEF:([^\|]*\|){3}(|({auth_method}[^\|]+))\|(|({protocol}[^\|]+))\|""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d+)""",
    """\Wcs3=\(({role}[^=:]+?):({protocol}[^=:]+?)\)""",
    """\Wresponsetime=({response_time}\d+)""",
    """\Wduid=(|({subject}.+?))(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wmsg=(|({outcome}.+?))(\s+\w+=|\s*$)""",
    """\Wcs1=(|({app}.+?))(\s+\w+=|\s*$)""",
    """\Wcs2=(|({connection_id}.+?))(\s+\w+=|\s*$)""",
    """\Wdvchost=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\Wcs4=(|({adopter_id}.+?))(\s+\w+=|\s*$)""",
    """\WexternalId=(|tid:({tracking_id}.+?))(\s+\w+=|\s*$)""",
    """\Wcs5=(|({local_user_id}.+?))(\s+\w+=|\s*$)""",
    """\Wcs6=(|({attributes}.+?))(\s+\w+=|\s*$)""",
    """\WSAML_SUBJECT\\=(|({user_email}[^=@]+?@[^=@]+?),?|({user}.+?))(\s+\w+\\=|\s*$)""",
  ]
  DupFields = [ "auth_method->activity" ]
}
```