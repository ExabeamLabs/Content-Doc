#### Parser Content
```Java
{
Name = cef-mimecast-security-alert
  Vendor = Mimecast
  Product = Email Security
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """destinationServiceName=Mimecast Email Security""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) ({host}[\w.\-]+) Skyformation""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wext_identifiers_0_=(|({alert_name}.+?))(\s+\w+=|\s*$)""",
    """\Wext_id=(|({alert_id}.+?))(\s+\w+=|\s*$)""",
    """\Wext_action=(|({outcome}.+?))(\s+\w+=|\s*$)""",
    """\Wext_recipientAddress=(|({recipient}.+?))(\s+\w+=|\s*$)""",
    """\Wext_senderAddress=(|({sender}.+?))(\s+\w+=|\s*$)""",
    """\Wext_impersonationResults_0__stringSimilarToDomain=(|({additional_info}.+?))(\s+\w+=|\s*$)""",
    """ext_subject=(|({subject}.+?))\s+ext_""",
    """ext_fileName=({file_name}.+?)\sext_senderAddress""",
    """ext_fileType=({file_type}[^=]+?)\sext_date""",
    """ext_actionTriggered=({outcome}.+?)\sext_details""",
  ]
}
```