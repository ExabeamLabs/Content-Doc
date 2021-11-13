#### Parser Content
```Java
{
Name = cef-mcafee-dlp-alert-2
      Vendor = McAfee
      Product = McAfee DLP
      Lms = ArcSight
      DataType = "dlp-alert"
      TimeFormat = "epoch"
      Conditions = [ """CEF:""", """|McAfee|SiteAdvisor Enterprise|""" ]
      Fields = [
        """exabeam_host=({host}[^\s]{1,2000})""",
        """\WeventId=(|({alert_id}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
        """\WcategoryOutcome=(|/({action}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
        """\WcategoryObject=(|({target}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wseverity=({alert_severity}\d{1,100})""",
        """\Wact=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wrt=({time}\d{1,100})(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wsuid=(|(({domain}[^\\\/=]{1,2000}?)[\\\/]{1,2000})?({user}[^\\\/=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wsntdom=(|({domain}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wrequest=(|({malware_url}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wdvc=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wdvchost=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wcatdt=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)"""
        """\WrequestProtocol=(|({protocol}.+?))\s\w+=""", 
      ]
      DupFields = ["alert_type->alert_name"]
    

}
```