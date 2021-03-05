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
        """exabeam_host=({host}[^\s]+)""",
        """\WeventId=(|({alert_id}.+?))(\s+\w+=|\s*$)""",
        """\WcategoryOutcome=(|/({action}.+?))(\s+\w+=|\s*$)""",
        """\WcategoryObject=(|({target}.+?))(\s+\w+=|\s*$)""",
        """\Wseverity=({alert_severity}\d+)""",
        """\Wact=(|({outcome}.+?))(\s+\w+=|\s*$)""",
        """\Wrt=({time}\d+)(\s+\w+=|\s*$)""",
        """\Wsuid=(|(({domain}[^\\\/=]+?)[\\\/]+)?({user}[^\\\/=]+?))(\s+\w+=|\s*$)""",
        """\Wsntdom=(|({domain}.+?))(\s+\w+=|\s*$)""",
        """\Wrequest=(|({malware_url}.+?))(\s+\w+=|\s*$)""",
        """\Wdvc=(|({host}.+?))(\s+\w+=|\s*$)""",
        """\Wdvchost=(|({host}.+?))(\s+\w+=|\s*$)""",
        """\Wcatdt=(|({alert_type}.+?))(\s+\w+=|\s*$)"""
        """\WrequestProtocol=(|({protocol}.+?))\s\w+=""", 
        """\Wdntdom=[^\s]*?\.?({top_domain}[^\/\.\s]+)(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))""",
      ]
      DupFields = ["alert_type->alert_name"]
    }
```