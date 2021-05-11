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
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\Wcs3=\(({role}[^=:]+?):({protocol}[^=:]+?)\)""",
    """\Wresponsetime=({response_time}\d{1,100})""",
    """\Wduid=(|({subject}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wmsg=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs1=(|({app}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs2=(|({connection_id}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvchost=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs4=(|({adopter_id}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WexternalId=(|tid:({tracking_id}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs5=(|({local_user_id}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs6=(|({attributes}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WSAML_SUBJECT\\=(|({user_email}[^=@]+?@[^=@]+?),?|({user}.+?))(\s{1,100}\w+\\=|\s{0,100}$)""",
  ]
  DupFields = [ "auth_method->activity" ]
}
```