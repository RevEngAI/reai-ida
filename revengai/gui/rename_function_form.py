#
# Example code not used
#
# import ida_kernwin
# import os


# class busy_form_t(ida_kernwin.Form):
#     class test_chooser_t(ida_kernwin.Choose):
#         """
#         A simple chooser to be used as an embedded chooser
#         """

#         def __init__(self, title, nb=5, flags=ida_kernwin.Choose.CH_MULTI):
#             ida_kernwin.Choose.__init__(
#                 self,
#                 title,
#                 [
#                     ["Address", 10 | ida_kernwin.Choose.CHCOL_HEX],
#                     ["Name", 30 | ida_kernwin.Choose.CHCOL_HEX],
#                 ],
#                 flags=flags,
#                 embedded=True,
#                 width=30,
#                 height=6,
#             )
#             self.items = [[str(x), "func_%04d" % x] for x in range(nb + 1)]
#             self.icon = 5

#         def OnGetLine(self, n):
#             print("getline %d" % n)
#             return self.items[n]

#         def OnGetSize(self):
#             n = len(self.items)
#             print("getsize -> %d" % n)
#             return n

#     def __init__(self):
#         self.invert = False
#         F = ida_kernwin.Form
#         F.__init__(
#             self,
#             r"""STARTITEM {id:rNormal}
# BUTTON YES* Yeah
# BUTTON NO Nope
# BUTTON CANCEL Nevermind
# Form Test

# {FormChangeCb}
# This is a string:  |+{cStr1}+
# This is an address:|+{cAddr1}+
# This is some HTML: |+{cHtml1}+
# This is a number:  |+{cVal1}+

# <#Hint1#Enter text  :{iStr1}>
# <#Hint2#Select color:{iColor1}>
# Browse test
# <#Select a file to open#Browse to open:{iFileOpen}>
# <#Select a file to save#Browse to save:{iFileSave}>
# <#Select dir#Browse for dir:{iDir}>
# Misc
# <##Enter a selector value:{iSegment}>
# <##Enter a raw hex       :{iRawHex}>
# <##Enter a character     :{iChar}>
# <##Enter an address      :{iAddr}>
# <##Write a type name     :{iType}>
# Button test: <##Button1:{iButton1}> <##Button2:{iButton2}>

# <##Check boxes##Error output:{rError}> | <##Radio boxes##Green:{rGreen}>
# <Normal output:{rNormal}>              | <Red:{rRed}>
# <Warnings:{rWarnings}>{cGroup1}>       | <Blue:{rBlue}>{cGroup2}>

# <Embedded chooser:{cEChooser}>
# The end!
# """,
#             {
#                 "cStr1": F.StringLabel("Hello"),
#                 "cHtml1": F.StringLabel(
#                     "<span style='color: red'>Is this red?<span>", tp=F.FT_HTML_LABEL
#                 ),
#                 "cAddr1": F.NumericLabel(0x401000, F.FT_ADDR),
#                 "cVal1": F.NumericLabel(99, F.FT_HEX),
#                 "iStr1": F.StringInput(),
#                 "iColor1": F.ColorInput(),
#                 "iFileOpen": F.FileInput(open=True),
#                 "iFileSave": F.FileInput(save=True),
#                 "iDir": F.DirInput(),
#                 "iType": F.StringInput(tp=F.FT_TYPE),
#                 "iSegment": F.NumericInput(tp=F.FT_SEG),
#                 "iRawHex": F.NumericInput(tp=F.FT_RAWHEX),
#                 "iAddr": F.NumericInput(tp=F.FT_ADDR),
#                 "iChar": F.NumericInput(tp=F.FT_CHAR),
#                 "iButton1": F.ButtonInput(self.OnButton1),
#                 "iButton2": F.ButtonInput(self.OnButton2),
#                 "cGroup1": F.ChkGroupControl(("rNormal", "rError", "rWarnings")),
#                 "cGroup2": F.RadGroupControl(("rRed", "rGreen", "rBlue")),
#                 "FormChangeCb": F.FormChangeCb(self.OnFormChange),
#                 "cEChooser": F.EmbeddedChooserControl(busy_form_t.test_chooser_t("E1")),
#             },
#         )

#     def OnButton1(self, code=0):
#         print("Button1 pressed")

#     def OnButton2(self, code=0):
#         print("Button2 pressed")

#     def OnFormChange(self, fid):
#         if fid == self.iButton1.id:
#             print("Button1 fchg;inv=%s" % self.invert)
#             self.SetFocusedField(self.rNormal)
#             self.EnableField(self.rError, self.invert)
#             self.invert = not self.invert
#         elif fid == self.iButton2.id:
#             g1 = self.GetControlValue(self.cGroup1)
#             g2 = self.GetControlValue(self.cGroup2)
#             d = self.GetControlValue(self.iDir)
#             f = self.GetControlValue(self.iFileOpen)
#             print("cGroup2:%x;Dir=%s;fopen=%s;cGroup1:%x" % (g1, d, f, g2))
#         elif fid == self.cEChooser.id:
#             l = self.GetControlValue(self.cEChooser)
#             print("Chooser: %s" % l)
#         elif fid in [self.rGreen.id, self.rRed.id, self.rBlue.id]:
#             color = {
#                 self.rGreen.id: 0x00FF00,
#                 self.rRed.id: 0x0000FF,
#                 self.rBlue.id: 0xFF0000,
#             }
#             self.SetControlValue(self.iColor1, color[fid])
#         elif fid == self.iColor1.id:
#             print("Color changed: %06x" % self.GetControlValue(self.iColor1))
#         else:
#             print(">>fid:%d" % fid)
#         return 1

#     @staticmethod
#     def compile_and_fiddle_with_fields():
#         f = busy_form_t()
#         f, args = f.Compile()
#         print(args[0])
#         print(args[1:])
#         f.rNormal.checked = True
#         f.rWarnings.checked = True
#         print(hex(f.cGroup1.value))

#         f.rGreen.selected = True
#         print(f.cGroup2.value)
#         print("Title: '%s'" % f.title)

#         f.Free()

#     @staticmethod
#     def test():
#         f = busy_form_t()

#         # Compile (in order to populate the controls)
#         f.Compile()

#         f.iColor1.value = 0x5BFFFF
#         f.iDir.value = os.getcwd()
#         f.iChar.value = ord("a")
#         f.rNormal.checked = True
#         f.rWarnings.checked = True
#         f.rGreen.selected = True
#         f.iStr1.value = "Hello"
#         f.iFileSave.value = "*.*"
#         f.iFileOpen.value = "*.*"

#         # Execute the form
#         ok = f.Execute()
#         print("r=%d" % ok)
#         if ok == 1:
#             print("f.str1=%s" % f.iStr1.value)
#             print("f.color1=%x" % f.iColor1.value)
#             print("f.openfile=%s" % f.iFileOpen.value)
#             print("f.savefile=%s" % f.iFileSave.value)
#             print("f.dir=%s" % f.iDir.value)
#             print("f.type=%s" % f.iType.value)
#             print("f.seg=%s" % f.iSegment.value)
#             print("f.rawhex=%x" % f.iRawHex.value)
#             print("f.char=%x" % f.iChar.value)
#             print("f.addr=%x" % f.iAddr.value)
#             print("f.cGroup1=%x" % f.cGroup1.value)
#             print("f.cGroup2=%x" % f.cGroup2.value)
#             sel = f.cEChooser.selection
#             if sel is None:
#                 print("No selection")
#             else:
#                 print("Selection: %s" % sel)

#         # Dispose the form
#         f.Free()
