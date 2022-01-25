#### Parser Content
```Java
{
Name = cef-okta-app-activity
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName =Okta""", """cs6=""", """"targets":""", """"eventId":""" ]
  Fields=[
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"published":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """\Wfname=({object}(?![\w\-]{25}).+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """"action":[^}]{1,2000}?"message":"({additional_info}[^"]{1,2000})""",
    """"action":[^}]{1,2000}?"objectType":"({activity}[^"]{1,2000})""",
    """"(targets|actors)":[^\]]{1,2000}?"objectType":"User"[^\]\}]{1,2000}?"displayName":"((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]{1,2000}))""",
    """"(targets|actors)":[^\]]{1,2000}?"displayName":"((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]{1,2000}))[^\]\}]{1,2000}?"objectType":"User"""",
    """(s|d)?user\\*=({user_email}[^\s@,]{1,2000}@({email_domain}[^\s@,]{1,2000}))""",
    """(s|d)?user\\*=(anonymous|({user}[^\s@,]{1,2000}))(\s|\||,)""",
    """"(targets|actors)":[^\]]{1,2000}?"objectType":"User"[^\]\}]{1,2000}?"login":"({user_email}[^"]{1,2000})""",
    """"(targets|actors)":[^\]]{1,2000}?"login":"({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))[^\]\}]{1,2000}?"objectType":"User"""",
    """"actors":[^\]]{1,2000}?"objectType":"Client"[^\]\}]{1,2000}?"displayName":"(UNKNOWN|({browser}[^"]{1,2000}))""",
    """"actors":[^\]]{1,2000}?"displayName":"(UNKNOWN|({browser}[^"]{1,2000}))[^\]\}]{1,2000}?"objectType":"Client"""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"actors":[^\]]{1,2000}?"objectType":"Client"[^\]\}]{1,2000}?"ipAddress":"(|({src_ip}[^"]{1,2000}))""",
    """"actors":[^\]]{1,2000}?"ipAddress":"(|({src_ip}[^"]{1,2000}))[^\]\}]{1,2000}?"objectType":"Client"""",
    """"target(s)?":[^\]]{1,2000}?"objectType":"User"[^\]\}]{1,2000}?"displayName":"({target_user}[^"]{1,2000})""",
    """"target(s)?":[^\]]{1,2000}?"displayName":"({target_user}[^"]{1,2000})[^\]\}]{1,2000}?"objectType":"User"""",
    """"target(s)?":[^\]\}]{1,2000}?"objectType":"({object_type}[^"]{1,2000})""",
    """"actors":[^\]]{1,2000}?"objectType":"Client"[^\]\}]{1,2000}?"id":"({user_agent}[^"]{1,2000})""",
    """"actors":[^\]]{1,2000}?"id":"({user_agent}[^"]{1,2000})[^\]\}]{1,2000}?"objectType":"Client"""",
    """"actors":[^\]]{1,2000}?"objectType":"Client"[^\]\}]{1,2000}?"id":"[^"]{1,2000}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}"""",
    """"actors":[^\]]{1,2000}?"id":"[^"]{1,2000}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}"[^\]\}]{1,2000}?"objectType":"Client"""",
    """({app}Okta)""",
    """"id":"({object}[^"]{1,2000})"[^\}\]]{0,2000}"objectType":"AppInstance"""",
    """"objectType":"AppInstance"[^\}\]]{0,2000}"id":"({object}[^"]{1,2000})"""",
    """requestClientApplication=({app}[^=]{1,2000}?)\s{0,100}\w+=""",
    """\Wsuid=(anonymous|({user_email}[^@=]{1,2000}@[^@=]{1,2000}?)|({user}[^\s=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """requestUri":\s{0,100}"({request_uri}[^"]{1,2000}?)\s{0,100}"""",
  ]


}
```