#!/usr/bin/env python3
#
# mgchkj.py
#
# Copyright (C) 2024-2025 by Jason Summers
# Terms of use: MIT license
#
# Checker ("linter") for "magic" files used by the "file" command
# (https://darwinsys.com/file/).
#
# Contact info as of 2025:
#  Development/website: https://github.com/jsummers/mgchkj
#  Email: jason1@pobox.com
#
# Main issues reported:
#
# * "Line has no effect"
#   Finds some lines that have no effect, usually because they have no
#    message, and no children. A warning does not mean the pattern is
#    logically incorrect -- it may just have dead code in it.
#
# * "Continuation message might be printed first"
#   This is a fairly crude checker that finds *some* cases where a
#   (presumably pathological) input file could cause an attribute to be
#   printed without the file format ever being printed.
#
# * "Pattern might depend on platform byte order"
#   Warns about rules that might work differently on different systems.
#   I acknowledge that some rules intentionally use native types to print
#   things like "native byte-order" or "byte-swapped", but it's debatable
#   whether that's good practice.
#   I also acknowledge that big-endian systems are rare nowadays, so this
#   may not be much of an issue in practice.
#
# Terminology note: Here, "rule" means a normal configuration line
# in the magic file: anything that's not a comment, blank line, or
# special "!" line.

import sys
import copy
import re

class MCJFileLevelException(Exception):
    pass

class fdatatype:
    def __init__(self):
        self.isnumber = False
        self.isint = False
        self.isunsigned = False
        self.standard_u_prefix = False
        self.nbo = False
        self.compat_type = False
        self.u_is_useless = False
        self.u_is_dubious = False
        self.has_string_modifiers = False
        self.bt_modifiers = False
        self.fieldsize = 0

class context:
    def __init__(ctx):
        ctx.quieter = False
        ctx.debug = False
        ctx.warning_level = 2
        ctx.type_re1 = re.compile(r'([a-zA-Z0-9_]+)([\-+/\&|%*\~^])(.*)$')
        ctx.val_re_base8 = re.compile('[+-]?0[0-7]*$')
        ctx.val_re_base10 = re.compile('[+-]?[1-9][0-9]*$')
        ctx.val_re_base16 = re.compile('[+-]?0x[0-9A-Fa-f]+$')
        ctx.firstword_lc_re = re.compile(r'([a-z][A-Za-z0-9]*)')
        ctx.no_uc_re = re.compile(r'[a-z0-9]+$')
        ctx.fmt_spec_re = re.compile(r'%([-.#0-9l]*)([sciduoxXeEfFgG])')
        ctx.fdatatypes = {}

class rule_context:
    def __init__(rule, ctx, fctx):
        rule.parent = None
        rule.linenum = 0
        rule.level = 0
        rule.text = ''
        rule.typefield1 = '' # w/o modifiers
        rule.typefield2 = '' # w/o modifiers or 'u' prefix
        rule.typefield_operator = ''
        rule.typefield_operand = ''
        rule.modifier_width = None
        rule.sanitized_string_opts = ''
        rule.valuefield = ''
        rule.valuefield_operator = '='
        rule.have_valuefield_number = False
        rule.valuefield_number = 0
        rule.valuefield_unescaped = ''
        rule.message = ''
        rule.has_child = False
        rule.has_format_specifier = False
        rule.format_specifier = ''
        rule.format_spec_flags = ''
        rule.likely_continuation_message = False
        # 0=narrow (equality), 1=broad, 2=wildcard
        rule.match_broadness = 2

        rule.default_handled = False
        rule.warnings_from_children = []

        rule.silence_cm_warning = False
        rule.silence_cm_warning_for_children = False
        rule.dsc_may_print_starter_msg = False
        # Number of descendants with a starter message,
        # by match 'broadness'.
        rule.num_dsc_with_sm_by_br = [0, 0, 0]
        rule.fdatatypeinfo = None
        rule.nbo_warning_handled = False
        rule.suspicious_octal = False

class file_context:
    def __init__(fctx, ctx):
        fctx.rule_stack = []
        fctx.name = 'noname'
        fctx.linenum = 0

#-------------------------------

class unescape_context:
    def __init__(self):
        self.output = ''
        self.escape_pending = False
        self.have_pending_int = False
        self.pending_int_base = 0
        self.max_digits_pending = 0
        self.digit_count = 0
        self.pending_int = 0
        self.suspicious_octal = False

def unescape_flush(ue):
    if ue.have_pending_int:
        ue.output += chr(ue.pending_int)
        if ue.pending_int_base==8 and ue.digit_count==2 and \
            ue.pending_int<8:
            ue.suspicious_octal = True
        ue.have_pending_int = False

def decode_ascii_digit(chn, base):
    if base==8:
        if chn>=48 and chn<=55:
            return chn-48, True
    elif base==16:
        if chn>=48 and chn<=57:
            return chn-48, True
        elif chn>=0x41 and chn<=0x46:
            return chn-55, True
        elif chn>=0x61 and chn<=0x66:
            return chn-87, True
    return 0, False

def unescape_addchar(ue, ch):
    chn = ord(ch)

    if ue.have_pending_int:
        val, ok = decode_ascii_digit(chn, ue.pending_int_base)
        if ok:
            ue.digit_count += 1
            ue.pending_int *= ue.pending_int_base
            ue.pending_int += val
            ue.max_digits_pending -= 1
            if ue.max_digits_pending<1:
                unescape_flush(ue)
            return
        else:
            unescape_flush(ue)

    if ue.escape_pending:
        if ch=='x':
            ue.have_pending_int = True
            ue.pending_int_base = 16
            ue.max_digits_pending = 2
            ue.pending_int = 0
            ue.digit_count = 0
        elif chn>=48 and chn<=55:
            ue.have_pending_int = True
            ue.pending_int_base = 8
            ue.max_digits_pending = 2
            ue.pending_int = chn-48
            ue.digit_count = 1
        else:
            ue.output += ch
        ue.escape_pending = False
    else:
        if chn==0x5c:
            ue.escape_pending = True
        else:
            ue.output += ch

def unescape_value(rule):
    t_escaped = rule.valuefield
    ue = unescape_context()
    for i in range(len(t_escaped)):
        unescape_addchar(ue, t_escaped[i])
    unescape_flush(ue)
    rule.valuefield_unescaped = ue.output
    if ue.suspicious_octal:
        rule.suspicious_octal = True

#-------------------------------

def del_warnings_from_children(rule):
    rule.warnings_from_children = []

def emit_and_del_warnings_from_children(rule):
    for w in rule.warnings_from_children:
        print(w)
    del_warnings_from_children(rule)

def format_warning2(fctx, msg, line_text):
    fullmsg = '%s:%d: %s [%s]' % \
        (fctx.name, fctx.linenum, msg, line_text)
    return fullmsg

def format_warning(ctx, fctx, rule, msg):
    fullmsg = '%s:%d: %s [%s]' % \
        (fctx.name, rule.linenum, msg, rule.text)
    return fullmsg

def emit_warning(ctx, fctx, rule, msg1):
    fullmsg = format_warning(ctx, fctx, rule, msg1)
    print(fullmsg)

def late_newarn_stuff(ctx, fctx, rule):
    # It's important to get the order of the following operations right.

    # ---- If this rule has warnings from its children, emit+delete them.
    emit_and_del_warnings_from_children(rule)

    # ---- Special rule types
    if rule.typefield2=='clear':
        if rule.parent is not None:
            emit_and_del_warnings_from_children(rule.parent)
            rule.parent.default_handled = False

    # If a rule has multiple "default" children, only the first can
    # match, unless there's a 'clear' between them.
    # (AFAICT, after a 'default', the has-a-child-matched flag is
    # guaranteed to be True, because the 'default' rule itself will
    # match if nothing else does.)
    unmatchable_default = False

    if rule.typefield2=='default':
        if rule.parent is not None:
            del_warnings_from_children(rule.parent)
            if rule.parent.default_handled:
                unmatchable_default = True
            rule.parent.default_handled = True

    # ----
    # In general, if a rule has no message and no children,
    # construct a warning message, and append it to the parent rule.
    # (If it has no parent, print it immediately)

    ne_flag = False
    if (not rule.has_child) and (rule.message == ''):
        ne_flag = True

    if rule.typefield2=='use' or rule.typefield2=='indirect' or \
        (rule.fdatatypeinfo is None):
        ne_flag = False

    if unmatchable_default:
        emit_warning(ctx, fctx, rule, "Unmatchable 'default' (due to "
            "previous 'default')")
        return

    if ne_flag:
        fullmsg = format_warning(ctx, fctx, rule, 'Line has no effect')

        if rule.parent is None:
            print(fullmsg)
        else:
            if ctx.debug:
                print('appending warning to parent')
            rule.parent.warnings_from_children.append(fullmsg)

# Invoke the warning, if needed.
def late_cmwarn_internal(ctx, fctx, rule):
    if rule.silence_cm_warning:
        return
    if not rule.likely_continuation_message:
        return

    nrules_by_br = [0, 0, 0]
    may_print_starter = False

    # This collects info from the previous children of our
    # ancestors. It doesn't count our actual ancestors, because
    # the counters are only updated right before a rule is
    # disposed of, and our ancestors are still on the stack.
    p = rule.parent
    while p is not None:
        for b in range(3):
            nrules_by_br[b] += p.num_dsc_with_sm_by_br[b]
        if p.dsc_may_print_starter_msg:
            may_print_starter = True
        p = p.parent

    if ctx.debug:
        print('wc bm nm', nrules_by_br[2], nrules_by_br[1], nrules_by_br[0])

    ne_warn = False
    if not may_print_starter:
        ne_warn = True
    elif nrules_by_br[2]>0:
        pass
    elif nrules_by_br[1]==0:
        ne_warn = True
    elif nrules_by_br[1]==1 and nrules_by_br[0]==0:
        ne_warn = True

    if ne_warn:
        fullmsg = format_warning(ctx, fctx, rule, \
            "Continuation message might be printed first")
        print(fullmsg)

def late_cmwarn_stuff(ctx, fctx, rule):
    if ctx.debug:
        print("broadness(l):", rule.match_broadness)
        print("silenced:", rule.silence_cm_warning)

    late_cmwarn_internal(ctx, fctx, rule)

    this_rule_may_print_starter_msg = False
    if (rule.message!='') and (not rule.likely_continuation_message):
        this_rule_may_print_starter_msg = True

    if rule.parent is not None:
        # Propagate flags from our children, to our parent
        if rule.dsc_may_print_starter_msg:
            rule.parent.dsc_may_print_starter_msg = True

        # Maybe new flags
        if rule.typefield2=='use':
            rule.parent.dsc_may_print_starter_msg = True
        elif rule.message=='':
            pass
        else:
            rule.parent.dsc_may_print_starter_msg = True


    if (rule.parent is not None) and (this_rule_may_print_starter_msg or \
        rule.dsc_may_print_starter_msg):

        # Take the data from our children, constrain it by
        # our own match broadness, and add it to our parent...
        for pb in range(3):
            pb_constrained = pb
            if pb_constrained > rule.match_broadness:
                pb_constrained = rule.match_broadness
            rule.parent.num_dsc_with_sm_by_br[pb_constrained] += \
                rule.num_dsc_with_sm_by_br[pb]

        #...and account for ourself.
        if this_rule_may_print_starter_msg:
            rule.parent.num_dsc_with_sm_by_br[rule.match_broadness] += 1

        if ctx.debug:
            print('parent now:', rule.parent.num_dsc_with_sm_by_br[2], \
                rule.parent.num_dsc_with_sm_by_br[1], \
                rule.parent.num_dsc_with_sm_by_br[0])

    if ctx.debug:
        print("child msgs:", rule.dsc_may_print_starter_msg)

        print("child br counts:", \
            rule.num_dsc_with_sm_by_br[2], \
            rule.num_dsc_with_sm_by_br[1], \
            rule.num_dsc_with_sm_by_br[0])

def finish_rule(ctx, fctx, rule):
    if ctx.debug:
        print("pop rule@%d" % (rule.linenum))

    late_newarn_stuff(ctx, fctx, rule)
    late_cmwarn_stuff(ctx, fctx, rule)

def finish_all_except_n_rules(ctx, fctx, n):
    while len(fctx.rule_stack)>n:
        r = fctx.rule_stack.pop()
        finish_rule(ctx, fctx, r)

def early_cmwarn_stuff(ctx, fctx, rule):
    # Note that here, parent.silence_cm_warning_for_children applies
    # only to our later siblings. The earlier ones have already
    # been fully processed.

    if rule.parent is not None:
        if rule.parent.silence_cm_warning or \
            rule.parent.silence_cm_warning_for_children:
            rule.silence_cm_warning = True

    # There's some ugly hacks here.
    # Let's assume we're pretty good at detecting that a
    # continuation message might be printed before a
    # "non-continuation message".
    # But we don't want to warn aobut every such continuation
    # message. We only want to warn about the ones that could be
    # the first thing printed, not those that can only be printed
    # after another continuation messages.
    # I'm not sure how to deal with that problem. But these
    # hacks will reduce the noise.

    if rule.typefield2=='use' or rule.typefield2=='indirect':
        rule.silence_cm_warning = True
        if rule.parent is not None:
            rule.parent.silence_cm_warning_for_children = True

    if rule.message!='' and rule.match_broadness==2:
        if rule.parent is not None:
            rule.parent.silence_cm_warning_for_children = True

    if rule.likely_continuation_message:
        rule.silence_cm_warning_for_children = True

    if rule.message!='' and not rule.likely_continuation_message:
        rule.silence_cm_warning = True

    if rule.typefield2=='name':
        rule.silence_cm_warning = True

# Helper function.
# Returns True if it looks like a cont. msg.;
# False means no info.
def continuation_lev2_tests(ctx, rule, msg):
    if (': ' in msg) or \
        ('=%' in msg) or \
        ('= %' in msg):
        pass
    else:
        return False

    # Likely continuation message if the first "word" starts
    # with a lc letter and has no uc letters.
    flag = False
    m1 = ctx.firstword_lc_re.match(msg)
    if m1:
        firstword = m1.group(1)
        m2 = ctx.no_uc_re.match(firstword)
        if m2:
            flag = True

    if not flag:
        return False
    return True

def looks_like_continuation_message(ctx, rule, msg):
    if len(msg)>=2:
        if msg[0:2]=="\\b":
            return True
        if msg[0]=='%' and rule.format_specifier!='s':
            return True
        if msg.startswith('version '):
            return True
        if ctx.warning_level>=2 and \
            rule.has_format_specifier and \
            rule.level>0 and \
            msg[0]>='a' and msg[0]<='z':
            if continuation_lev2_tests(ctx, rule, msg):
                return True

    if len(msg)>=1:
        if msg[0] in '(-,;:':
            return True
    return False

def set_more_rule_properties(ctx, fctx, rule):
    if len(rule.message)>=2:
        m1 = ctx.fmt_spec_re.search(rule.message)
        if m1:
            rule.has_format_specifier = True
            rule.format_spec_flags = m1.group(1)
            rule.format_specifier = m1.group(2)

    rule.likely_continuation_message = \
        looks_like_continuation_message(ctx, rule, rule.message)

    if rule.valuefield_operator=='x':
        rule.match_broadness = 2
    elif rule.typefield2=='use' or rule.typefield2=='name':
        rule.match_broadness = 2
    elif rule.typefield_operator=='&' or \
        rule.typefield_operator=='|' or \
        rule.typefield_operator=='%':
        # Certain operators in the 'type' field mean we
        # could be testing just a few
        # bits, in which case all the possible values might reasonably
        # be handled. We don't have a good way to deal with that.
        rule.match_broadness = 1
    else:
        if rule.valuefield_operator in '!<>&^':
            rule.match_broadness = 1
        else:
            rule.match_broadness = 0

    if rule.parent is not None:
        if rule.parent.nbo_warning_handled:
            rule.nbo_warning_handled = True

    if ctx.debug:
        print('rule@', rule.linenum)
        print('broadness(e):', rule.match_broadness)

# In the version of file I'm using, a regex (the 'value' field
# after one layer of unescaping) is an ASCII string, and cannot
# contain NUL bytes. A NUL byte will be interpreted as the end of
# the expression. If the truncated expression happens to be
# syntactically valid, there will be no error; it just won't work
# right.
def regexnul_warn(ctx, fctx, rule):
    if rule.typefield2 != 'regex':
        return
    if '\x00' in rule.valuefield_unescaped:
        emit_warning(ctx, fctx, rule, 'Regex might be truncated by NUL byte')

def stringlen_warn(ctx, fctx, rule):
    if rule.typefield2 != 'string':
        return
    if rule.modifier_width is None:
        return
    if len(rule.valuefield_unescaped) > rule.modifier_width:
        emit_warning(ctx, fctx, rule, \
            'String exceeds /<width> limit')

def line_has_ctrl_chars(s):
    for ch in s:
        n = ord(ch)
        if n==127 or (n<32 and n!=9):
            return 1
    return 0

# Returns 0=ascii, 1=utf-8, 2=unknown
def guess_line_encoding(s):
    utf8_flag = False
    for ch in s:
        n = ord(ch)
        if n>=127:
            if n==0xfffd:
                return 2
            else:
                utf8_flag = True
    if utf8_flag:
        return 1
    return 0

def spacecomma_warn(ctx, fctx, rule):
    if len(rule.message)<1 or rule.level==0:
        return
    # Should we also look for ':'? It's pretty common.
    if rule.message[0] in ',;':
        emit_warning(ctx, fctx, rule, 'Message might include an unwanted '
        'space; consider \\b')

def badquotes_warn(ctx, fctx, rule):
    # It's suspicious if:
    # the value starts with '"' and contains no other '"'; and
    # the message contains a '"'; and
    # the whitespace following the value consists of one space.
    if rule.message=='':
        return
    if not (rule.valuefield.startswith('"')):
        return
    if ('"' in rule.valuefield[1:]):
        return
    if rule.fieldsep[2]!=" ":
        return
    nq = rule.message.count('"')
    if nq==0:
        return
    if nq!=1 and ctx.warning_level<2:
        return
    emit_warning(ctx, fctx, rule, 'Possible incorrect use of quotes')

def number_is_palindrome(n, nbytes):
    if n<0:
        if n == -1:
            return True
        return False
    if nbytes==2:
        if (n>>8)==(n & 0xff):
            return True
    elif nbytes==4:
        if (n>>24)==(n & 0xff) and \
            ((n>>16)&0xff) == ((n>>8)&0xff):
            return True
    elif nbytes==8:
        if (n>>56)==(n & 0xff) and \
            ((n>>48)&0xff) == ((n>>8)&0xff) and \
            ((n>>40)&0xff) == ((n>>16)&0xff) and \
            ((n>>32)&0xff) == ((n>>24)&0xff):
            return True
    return False

def get_fdatatypeinfo(ctx, rule):
    rule.fdatatypeinfo = ctx.fdatatypes.get(rule.typefield1)
    if rule.fdatatypeinfo is not None:
        if rule.fdatatypeinfo.standard_u_prefix:
            rule.typefield2 = rule.typefield1[1:]

# Currently, this only supports integer types (not floating point)
def parse_valuefield_number(ctx, fctx, rule):
    if rule.fdatatypeinfo is None:
        return
    if not rule.fdatatypeinfo.isint:
        return

    pflag = False
    if rule.valuefield=='0':
        val = 0
        pflag = True

    if not pflag: # try octal
        m1 = ctx.val_re_base8.match(rule.valuefield)
        if m1:
            val = int(rule.valuefield, base=8)
            pflag = True

    if not pflag: # try decimal
        m1 = ctx.val_re_base10.match(rule.valuefield)
        if m1:
            val = int(rule.valuefield, base=10)
            pflag = True

    if not pflag: # try hex
        m1 = ctx.val_re_base16.match(rule.valuefield)
        if m1:
            val = int(rule.valuefield, base=16)
            pflag = True

    if pflag:
        rule.have_valuefield_number = True
        rule.valuefield_number = val

def nativebyteorder_warn(ctx, fctx, rule):
    # Don't warn if an ancestor rule already warned.
    # The theory is that if a rule relies on native byte order,
    # having its children also do so might be the least bad thing
    # thing to do.
    # This logic isn't perfect, but it reduces the noise, and there
    # will still be at least one warning per offending ruleset.
    if rule.nbo_warning_handled:
        return

    if rule.fdatatypeinfo is None:
        return
    if not rule.fdatatypeinfo.isnumber:
        return
    if not rule.fdatatypeinfo.nbo:
        return

    type_is_unsigned = rule.fdatatypeinfo.isunsigned;

    apply_whitelist = True

    if rule.typefield_operator!='':
        # A rule like ">0  ushort&0x000f  0  ..." is most likely
        # byte-order dependent.
        apply_whitelist = False

    val = 1 # arbitrary default
    if rule.fdatatypeinfo.isint:
        if rule.have_valuefield_number:
            val = rule.valuefield_number
            pflag = True

    else:
        # floating point, presumably
        if rule.valuefield=='0' or rule.valuefield=='0.0':
            val = 0

    if apply_whitelist:
        if val==0 and rule.valuefield_operator=='=':
            return
        if not rule.has_format_specifier:
            if (val==0 and rule.valuefield_operator=='!') \
                or rule.valuefield_operator=='x':
                return
            if type_is_unsigned and (val==0 and \
                rule.valuefield_operator=='>'):
                return

    whitelist_palindromes = apply_whitelist and \
        rule.fdatatypeinfo.isint and \
        (rule.valuefield_operator=='=' or \
        ((rule.valuefield_operator in r'!&^') and \
        not rule.has_format_specifier))
    # TODO: Not sure about '~' operator.

    if whitelist_palindromes:
        if number_is_palindrome(val, rule.fdatatypeinfo.fieldsize):
            return

    # TODO: Whitelist complex palindromic rules.
    emit_warning(ctx, fctx, rule,
        'Pattern might depend on platform byte order')
    rule.nbo_warning_handled = True

def uintrange_warn(ctx, fctx, rule):
    if rule.fdatatypeinfo is None:
        return
    if not rule.fdatatypeinfo.isint:
        return
    if not rule.fdatatypeinfo.isunsigned:
        return
    if not rule.have_valuefield_number:
        return

    warn_alwaysfalse = False
    warn_alwaystrue = False

    if rule.valuefield_operator=='=':
        if rule.valuefield_number<0:
            warn_alwaysfalse = True

    if rule.valuefield_operator=='<':
        if rule.valuefield_number<=0:
            warn_alwaysfalse = True

    if rule.valuefield_operator=='>':
        if rule.valuefield_number<0:
            warn_alwaystrue = True

    # I haven't figured out exactly what happens in every situation,
    # so the warning message is noncommittal.
    if warn_alwaysfalse or warn_alwaystrue:
        emit_warning(ctx, fctx, rule,
            "Dubious comparison of unsigned int to negative number")

def byte_compare_warn(ctx, fctx, rule):
    # Should we also check types 'dC' and 'd1'? I'm undecided.
    if rule.typefield1 != 'byte':
        return
    if not rule.have_valuefield_number:
        return
    if rule.typefield_operator!='':
        return

    warn_lt = False
    warn_gt = False

    # If the number in the "test" field is >=0x80, file does an unsigned
    # comparison, and all is well. The "gotcha" numbers are from 0 to 0x7f.
    if rule.valuefield_operator=='<':
        if rule.valuefield_number>=1 and rule.valuefield_number<=0x7f:
            warn_lt = True
    elif rule.valuefield_operator=='>':
        if rule.valuefield_number>=0 and rule.valuefield_number<=0x7f:
            warn_gt = True

    # There will be false positives. Sometimes, the field really is a
    # signed byte. Probably more likely, the combination of this rule
    # and another rule ultimately handles the negative values correctly.
    # That's too difficult for us to detect.
    if warn_lt:
        emit_warning(ctx, fctx, rule,
            "Suspicious signed comparison, will match values >=0x80")
    if warn_gt:
        emit_warning(ctx, fctx, rule,
            "Suspicious signed comparison, will not match values >=0x80")

def signed_with_percentu_warn(ctx, fctx, rule):
    # For the purposes of printing, a 1- or 2-byte signed int apparently
    # gets promoted to a 4-byte signed int, then reinterpreted as an
    # unsigned 4-byte int if %u is used.
    # For example, a byte value 0xff will be printed not as "255" or "-1",
    # but as "4294967295".
    # This test will have false positives (a previous test might have
    # ensured the value is positive), but even then maybe this mismatch
    # ought to be fixed.

    if not rule.has_format_specifier:
        return
    if rule.format_specifier not in ['u', 'o', 'x', 'X']:
        return

    if rule.fdatatypeinfo is None:
        return
    if not rule.fdatatypeinfo.isnumber:
        return
    if rule.fdatatypeinfo.isunsigned:
        return
    if rule.fdatatypeinfo.fieldsize==1:
        tname = 'byte'
    elif rule.fdatatypeinfo.fieldsize==2:
        tname = 'short'
    else:
        return

    emit_warning(ctx, fctx, rule, 'Signed %s with %%%s format '
        'might print nonsense' % (tname, rule.format_specifier))

def unused_type_operator_warn(ctx, fctx, rule):
    # This check only applies to numeric types.
    if rule.fdatatypeinfo is None:
        return
    if not rule.fdatatypeinfo.isnumber:
        return

    if (not rule.has_format_specifier) and \
        rule.typefield_operator!='' and \
        rule.valuefield_operator=='x':
        # This is likely intentional, if the rule is accompanied by other
        # rules that do the same operation. But I think it's worth a warning.
        emit_warning(ctx, fctx, rule,
            "Unused '%s' operation in type field" % \
            (rule.typefield_operator))

def ishexdigit(s):
    return s.isdecimal() or (s>="a" and s<="f") or \
        (s>="A" and s<="F")

# The options can have a hex number embedded in them,
# so a 'b' might be a hex digit, not the 'b' modifier.
# I don't see any way to cheat -- we'll have to parse it.
def sanitize_string_opts(rule):
    s1 = rule.typefield_operand
    s2 = ''
    in_width = False
    width_as_string = ''
    width_base = 10
    skip1 = False

    for i in range(len(s1)):
        a = s1[i]
        if skip1:
            a = ""
            skip1 = False
        elif in_width and (width_base==8 or width_base==10):
            if s1[i].isdecimal():
                width_as_string += s1[i]
                a = ""
            else:
                in_width = False
        elif in_width and width_base==16:
            if ishexdigit(s1[i]):
                width_as_string += s1[i]
                a = ""
            else:
                in_width = False
        else:
            if s1[i].isdecimal():
                width_as_string = ""
                if s1[i]=="0" and (i+1<len(s1)) and \
                    (s1[i+1]=="x" or s1[i+1]=="X"):
                    in_width = True
                    width_base = 16
                    skip1 = True
                elif s1[i]=="0":
                    in_width = True
                    width_base = 8
                else:
                    in_width = True
                    width_base = 10
                width_as_string += s1[i]
                # TODO: This isn't needed anymore.
                a = "0" # Collapse numbers to "0"
        s2 += a

    rule.sanitized_string_opts = s2
    if width_as_string:
        rule.modifier_width = int(width_as_string, base=width_base)

def datatype_warnings(ctx, fctx, rule):
    # Normally, 'file' will error out if there's an invalid type,
    # so this checker is not all that useful.
    # But file's parser is more permissive than ours (most whitespace
    # is optional), so we may catch some errors that happened to be
    # syntactically valid.
    if rule.fdatatypeinfo is None:
        emit_warning(ctx, fctx, rule,
            "Unrecognized type (or missing usual whitespace)")
        return

    if (ctx.warning_level>=3) and rule.level>0 and \
        rule.typefield_operator=='/' and \
        rule.fdatatypeinfo.bt_modifiers:
        opts = rule.sanitized_string_opts
        for flg in ['b', 't']:
            if flg in opts:
                # I'm not 100% sure this warning is always correct. It doesn't
                # seem to be made clear by the documentation, and the source
                # code is hard to understand. There is the comment "(set only
                # for top-level tests)" in file.h.
                emit_warning(ctx, fctx, rule,
                    "Modifier /%s has no effect at level>0" % (flg))

    if (ctx.warning_level>=3) and \
        (not rule.fdatatypeinfo.compat_type) and \
        rule.fdatatypeinfo.isunsigned:
        if rule.fdatatypeinfo.u_is_useless or \
            rule.fdatatypeinfo.u_is_dubious:
            emit_warning(ctx, fctx, rule,
                "Prefix 'u' on type '%s' is unusual" % (rule.typefield2))

def string16_warnings(ctx, fctx, rule):
    if ctx.warning_level<3:
        return
    if rule.fdatatypeinfo is None:
        return
    if rule.typefield2!='lestring16' and rule.typefield2!='bestring16':
        return
    if '0' in rule.sanitized_string_opts:
        emit_warning(ctx, fctx, rule,
            "Modifier /<width> might not be implemented for string16 types")

def valuemisc_warn(ctx, fctx, rule):
    if "\x09" in rule.valuefield:
        # I'm assuming an escaped literal tab is the only way we
        # could get here.
        emit_warning(ctx, fctx, rule,
            "Test string contains escaped tab; suggest \\t instead")

    # This is disabled (warning level 4 is unofficial). It's noisy,
    # and not likely to catch any errors that don't trigger the
    # escaped-tab warning.
    if ctx.warning_level>=4:
        if len(rule.valuefield)>=1 and rule.valuefield[-1]==" ":
            emit_warning(ctx, fctx, rule,
                "Test string ends with escaped space; suggest \\x20 instead")

def messagemisc_warn(ctx, fctx, rule):
    if len(rule.message) < 1:
        return

    if "\x09" in rule.message:
        emit_warning(ctx, fctx, rule, "Message contains a tab character")

    # Trailing whitespace is significant. There doesn't seem to be
    # any special handling of it.
    # While a trailing space can be mildly useful, I think it's
    # almost never a good idea.
    # We whitelist the message "\b ", because apparently it's an idiom
    # used as a dummy message, to attach certain annotations to (it
    # doesn't fully work, but maybe it's the best that can be done).
    if ctx.warning_level>=2:
        if (rule.message[-1]==" ") and (rule.message!="\\b "):
            emit_warning(ctx, fctx, rule, "Message ends with a space")

    if ctx.warning_level>=3:
        if "  " in rule.message:
            emit_warning(ctx, fctx, rule,
                "Message contains consecutive spaces")

def process_rule_early(ctx, fctx, rule):
    set_more_rule_properties(ctx, fctx, rule)
    get_fdatatypeinfo(ctx, rule)
    parse_valuefield_number(ctx, fctx, rule)
    if rule.fdatatypeinfo is not None and \
        rule.fdatatypeinfo.has_string_modifiers:
        sanitize_string_opts(rule)

    if rule.typefield2=='string' or  rule.typefield2=='regex':
        unescape_value(rule)
        if rule.suspicious_octal and ctx.warning_level>=2:
            emit_warning(ctx, fctx, rule, "Suspicious octal escape "
                "(two digits, useless leading 0)")

    datatype_warnings(ctx, fctx, rule)
    if ctx.warning_level>=2:
        nativebyteorder_warn(ctx, fctx, rule)
    uintrange_warn(ctx, fctx, rule)
    if ctx.warning_level>=3:
        byte_compare_warn(ctx, fctx, rule)
    if ctx.warning_level>=2:
        signed_with_percentu_warn(ctx, fctx, rule)
    if ctx.warning_level>=2:
        unused_type_operator_warn(ctx, fctx, rule)
    string16_warnings(ctx, fctx, rule)
    regexnul_warn(ctx, fctx, rule)
    stringlen_warn(ctx, fctx, rule)
    spacecomma_warn(ctx, fctx, rule)
    badquotes_warn(ctx, fctx, rule)
    valuemisc_warn(ctx, fctx, rule)
    messagemisc_warn(ctx, fctx, rule)
    early_cmwarn_stuff(ctx, fctx, rule)

def parse_one_line(ctx, fctx, line_text_orig, line_text_friendly):
    # Line format:  >>offset   type   value   message
    # fstate:
    #  0=init
    #  1=reading offset, 2=done with offset
    #  3=reading type, 4=done with type
    #  5=reading value, 6=done with value
    #  7=reading message

    # (Whitespace at the start of a line is *not* ignored.)
    if len(line_text_orig)==0:
        return None
    if line_text_orig[0:1]=='#':
        return None
    if line_text_orig[0:2]=='!:':
        return None

    rule = rule_context(ctx, fctx)
    rule.linenum = fctx.linenum
    rule.level = 0
    rule.text = line_text_friendly
    rule.text_orig = line_text_orig

    fstate = 1
    escape_flag = False
    internal_whitespace_flag = False
    field = [ '', '', '', '' ]
    rule.fieldsep = [ '', '', '' ] # the whitespace between fields

    for i in range(len(line_text_orig)):
        ch = line_text_orig[i]

        isws = (ch=='\x09') or (ch=='\x20')

        if fstate==1:
            if isws:
                rule.fieldsep[0] += ch
                fstate = 2
                continue
            field[0] += ch
            if ch=='>':
                rule.level += 1

        if fstate==2:
            if isws:
                rule.fieldsep[0] += ch
                continue
            fstate = 3

        if fstate==3:
            if isws:
                rule.fieldsep[1] += ch
                fstate = 4
                continue
            field[1] += ch

        if fstate==4:
            if isws:
                rule.fieldsep[1] += ch
                continue
            fstate = 5

        if fstate==5:
            if isws and internal_whitespace_flag:
                # For convenience later, we don't save the internal whitespace
                # in field[2].
                continue
            internal_whitespace_flag = False
            if escape_flag:
                field[2] += ch
                escape_flag = False
                continue
            # Whitespace can occur after the match operator, for some reason.
            if field[2]=='' and (ch in '!=<>&^~'):
                internal_whitespace_flag = True
            if isws:
                rule.fieldsep[2] += ch
                fstate = 6
                continue
            if ch=='\\':
                escape_flag = True
            field[2] += ch

        if fstate==6:
            if isws:
                rule.fieldsep[2] += ch
                continue
            fstate = 7

        if fstate==7:
            field[3] += ch

    if ctx.debug:
        print("%d|%d|%d|%s|%s|%s|%s|" % (fctx.linenum, level, \
            fstate, field[0], field[1], field[2], field[3]))

    rule.typefield1 = field[1]
    m1 = ctx.type_re1.match(rule.typefield1)
    if m1:
        rule.typefield1 = m1.group(1)
        rule.typefield_operator = m1.group(2)
        rule.typefield_operand = m1.group(3)
    rule.typefield2 = rule.typefield1 # default

    if field[2]=='x':
        rule.valuefield = ''
        rule.valuefield_operator = 'x'
    elif field[2][0:1] in r'=<>&^~!':
        rule.valuefield = field[2][1:]
        rule.valuefield_operator = field[2][0:1]
    else:
        rule.valuefield = field[2]

    rule.message = field[3]
    # This is a bit of a hack, but a message of just "\b" (without trailing
    # whitespace) seems to be processed as if there were no message.
    if rule.message=="\\b":
        rule.message = ""

    return rule

def ctrlchar_warn(ctx, fctx, line_text_friendly):
    if not line_has_ctrl_chars(line_text_friendly):
        return

    fullmsg = format_warning2(fctx, \
        "Line has unexpected control characters", line_text_friendly)
    print(fullmsg)

def nonascii_warn(ctx, fctx, line_text_friendly):
    n = guess_line_encoding(line_text_friendly)

    # I don't know what encoding these files are supposed to use.
    # We warn about anything not UTF-8-compatible, and with -w3 about
    # anything not ASCII.
    if n==0:
        return
    if n==1 and ctx.warning_level<3:
        return

    if n==1:
        str="probably UTF-8"
    else:
        str="probably not UTF-8"
    fullmsg = format_warning2(fctx, \
        "Line has non-ASCII characters (%s)" % (str), line_text_friendly)
    print(fullmsg)

# Checkers that also apply to comment lines, etc.
def anyline_tests(ctx, fctx, line_text_friendly):
    if ctx.warning_level>=2:
        nonascii_warn(ctx, fctx, line_text_friendly)
    ctrlchar_warn(ctx, fctx, line_text_friendly)

def one_line(ctx, fctx, line_text, line_text_friendly):
    rule = parse_one_line(ctx, fctx, line_text, line_text_friendly)

    # TODO: Maybe some tests should have access to orig line_text
    if len(line_text_friendly)>0:
        anyline_tests(ctx, fctx, line_text_friendly)

    if rule is None:
        return

    if rule.level > len(fctx.rule_stack):
        print("Error: Bad nesting level, line", rule.linenum)
        raise MCJFileLevelException()

    # Process all the stacked-up rules at a greater than or equal
    # continuation level.
    if rule.level < len(fctx.rule_stack):
        finish_all_except_n_rules(ctx, fctx, rule.level)

    # ----

    if rule.level>0:
        rule.parent = fctx.rule_stack[rule.level-1]
        rule.parent.has_child = True
    else:
        rule.parent = None

    # Things to do when/before pushing the rule

    process_rule_early(ctx, fctx, rule)

    # Push the new rule onto the stack

    if ctx.debug:
        print('push rule@%d' % (rule.linenum))
    fctx.rule_stack.append(rule)

def make_friendly_msg(ctx, l1):
    l2 = ''
    wscount = 0
    for i in range(len(l1)):
        ch = l1[i]
        if ch==' ' or ch=='\x09':
            # Convert tabs to spaces, and limit the length of runs of
            # spaces in our output messages.
            wscount += 1
            if wscount<=3:
                l2 += ' '
        else:
            l2 += ch
            wscount = 0

    return l2

def onefile_main(ctx, fctx):
    for line in fctx.inf:
        fctx.linenum += 1
        line_text_orig = line.rstrip('\n')
        line_text_friendly = make_friendly_msg(ctx, line_text_orig)
        one_line(ctx, fctx, line_text_orig, line_text_friendly)

def onefile(ctx, fn):
    fctx = file_context(ctx)
    fctx.name = fn
    if not ctx.quieter:
        print("# Reading", fctx.name)

    try:
        fctx.inf = open(fn, "r", encoding='utf8', newline='\n', \
            errors='replace')
    except OSError as err:
        print("Error:", err)
        return

    try:
        onefile_main(ctx, fctx)
        finish_all_except_n_rules(ctx, fctx, 0) # I.e., finish all rules
    except MCJFileLevelException:
        pass
    finally:
        fctx.inf.close()

def init_datatypes(ctx):
    # i=integer, number
    # f=floating point, number
    # C=compatibility int type
    # 1,2,4,8=Field size
    # V='u' prefix is useless (TODO: Figure out when u makes sense.)
    # v='u' prefix is dubious
    # S=has "string"-style modifiers
    # T=allows /b & /t modifiers
    items = [
        'byte i1',
        'dC 1C',
        'd1 1C',
        'uC 1C',
        'u1 1C',
        'short i2n',
        'dS 2nC',
        'd2 2nC',
        'uS 2nC',
        'u2 2nC',
        'leshort i2',
        'beshort i2',
        'beshort i2',
        'leshort i2',
        'msdosdate i2nv',
        'msdostime i2nv',
        'bemsdosdate i2v',
        'bemsdostime i2v',
        'lemsdosdate i2v',
        'lemsdostime i2v',
        'long i4n',
        'dI 4nC',
        'dL 4nC',
        'd4 4nC',
        'd 4nC',
        'uI 4nC',
        'uL 4nC',
        'u4 4nC',
        'u 4nC',
        'belong i4',
        'lelong i4',
        'melong i4',
        'date i4n',
        'ldate i4n',
        'bedate i4',
        'ledate i4',
        'beldate i4',
        'leldate i4',
        'medate i4',
        'meldate i4',
        'quad i8n',
        'dQ 8nC',
        'd8 8nC',
        'uQ 8nC',
        'u8 8nC',
        'lequad i8',
        'bequad i8',
        'offset i8',
        'qdate i8n',
        'qldate i8n',
        'qwdate i8n',
        'beqwdate i8',
        'leqwdate i8',
        'leqdate i8',
        'beqdate i8',
        'leqldate i8',
        'beqldate i8',
        'float f4nv',
        'befloat f4v',
        'lefloat f4v',
        'double f8nv',
        'bedouble f8v',
        'ledouble f8v',
        'name VS',
        'use VS',
        'clear V',
        'default V',
        'indirect V',
        'string vST',
        'pstring vST',
        'regex vST',
        'bestring16 vS',
        'lestring16 vS',
        'search vST',
        'guid v',
        'der ',
        'bevarint ',
        'levarint ',
        'octal S',
        'leid3 ',
        'beid3 ' ]

    for iraw in items:
        ilist = iraw.split(' ', 1)
        x = fdatatype()
        if 'i' in ilist[1]:
            x.isnumber = True
            x.isint = True
        if 'f' in ilist[1]:
            x.isnumber = True
        if 'n' in ilist[1]:
            x.nbo = True
        if '1' in ilist[1]:
            x.fieldsize = 1
        if '2' in ilist[1]:
            x.fieldsize = 2
        if '4' in ilist[1]:
            x.fieldsize = 4
        if '8' in ilist[1]:
            x.fieldsize = 8
        if 'C' in ilist[1]:
            x.compat_type = True
            x.isnumber = True
            x.isint = True
            x.standard_u_prefix = False
        if 'V' in ilist[1]:
            x.u_is_useless = True
        if 'v' in ilist[1]:
            x.u_is_dubious = True
        if 'S' in ilist[1]:
            x.has_string_modifiers = True
        if 'T' in ilist[1]:
            x.bt_modifiers = True

        if x.compat_type:
            if ilist[0].startswith('u'):
                x.isunsigned = True
            else:
                x.isunsigned = False
            ctx.fdatatypes[ilist[0]] = x
        else:
            # 'u' prefix is always legal, except for compatibility types.
            y = copy.copy(x)
            x.isunsigned = False
            x.standard_u_prefix = False
            y.isunsigned = True
            y.standard_u_prefix = True
            ctx.fdatatypes[ilist[0]] = x
            ctx.fdatatypes['u' + ilist[0]] = y

def usage():
    print("mgchkj")
    print("Usage: mgchkj.py [options] file1 [file2...]")
    print("Options:")
    print(" -w1  Print fewer warnings")
    print(" -w2  Default warning level")
    print(" -w3  Print all warnings")

def main():
    ctx = context()
    filecount = 0

    for i in range(1, len(sys.argv)):
        if sys.argv[i][0]=='-':
            if sys.argv[i][1]=='q':
                ctx.quieter = True
            elif sys.argv[i][1]=='d':
                ctx.debug = True
            elif sys.argv[i][1]=='w':
                lv = sys.argv[i][2]
                if lv>='1' and lv<='9':
                    ctx.warning_level = int(lv)
        else:
            filecount = filecount+1

    if filecount==0:
        usage()
        return

    init_datatypes(ctx)

    for i in range(1, len(sys.argv)):
        if sys.argv[i][0]!='-':
            onefile(ctx, sys.argv[i])

main()
