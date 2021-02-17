#### Parser Content
```Java
{
Name = json-4723-1
  DataType = "windows-password-change"
  Conditions = [ """"event_id":4723""", """An attempt was made to change an account's password""" ]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}An attempt was made to change an account's password)""",
    """"TargetSid"+:"+({target_user_sid}[^"]+)""",
    """"hostname"+:"+(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|({dest_host}[^"]+))""",
  ]
}
```