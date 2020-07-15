/*
 *  This processor extension module extends the IBM S390x to disassemble
 *  undocumented instructions.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <ua.hpp>

//--------------------------------------------------------------------------
// Context data for the plugin. This object is created by the init()
// function and hold all local data.
struct plugin_ctx_t : public plugmod_t {
  bool reentry = false;

  netnode s390x_node;
  bool hooked = false;

  plugin_ctx_t();
  ~plugin_ctx_t();

  // This function is called when the user invokes the plugin.
  virtual bool idaapi run(size_t) override;
  // This function is called upon some events.
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

  size_t ana(insn_t &insn);
};

static const char node_name[] = "$ s390x processor extender parameters";

enum s390x_insn_type_t {
  S390X_unkn_1b = CUSTOM_INSN_ITYPE,
  S390X_unkn_2b,
  S390X_servc,
};

//--------------------------------------------------------------------------
// Analyze an instruction and fill the 'insn' structure
size_t plugin_ctx_t::ana(insn_t &insn) {
  if (this->reentry) {
    return 0;
  }

  // Be the fallback, so try to do a decode without this module first
  insn_t insn_org;
  this->reentry = true;
  int ret = decode_insn(&insn_org, insn.ea);
  this->reentry = false;
  if (ret) {
    // This module is not needed for this instruction
    return 0;
  }

  int code1 = get_byte(insn.ea);
  int code2 = get_byte(insn.ea+1);
  int size = (code1 >> 6) * 2;

  if (code1 == 0 || code1 == 0xff) {
    return 0;
  }

  // Cases of I, RR, RS, RSI, RX, SI, and SS formatted instructions
  // Alternatively, unknown families that could be other format but the whole
  // opcode family is not known.
  switch (code1) {
    case 0xA3: { insn.itype = S390X_unkn_1b; return size; } // Unknown
    case 0xAB: { insn.itype = S390X_unkn_1b; return size; } // Unknown
    case 0xC3: { insn.itype = S390X_unkn_1b; return size; } // Unknown
    case 0x81: { insn.itype = S390X_unkn_1b; return size; } // Unknown
  }

  // Cases of supported E, RRE, RRF, S, and SSE formatted instructions
  switch (code1 << 8 | code2) {
    case 0xB220: { insn.itype = S390X_servc; return size; }  // RRE
  }

  insn.itype = S390X_unkn_2b;
  return size;
}

//--------------------------------------------------------------------------
// Return the instruction mnemonics
const char *get_insn_mnem(const insn_t &insn) {
  if (insn.itype == S390X_servc)
    return "servc";
  return "<s390ext_error>";
}

//--------------------------------------------------------------------------
// This function can be hooked to various kernel events.
// In this particular plugin we hook to the HT_IDP group.
// As soon the kernel needs to decode and print an instruction, it will
// generate some events that we intercept and provide our own response.

// The quick & dirty approach.
// We just produce the instruction mnemonics along with its operands.
// No cross-references are created. No special processing.
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va) {
  switch (code)
  {
    case processor_t::ev_init:
      {
        msg("S390x processor extender initialized\n");
        plugin_ctx_t::run(0);
        break;
      }
    case processor_t::ev_term:
      {
        msg("S390x processor extender terminated\n");
        break;
      }
    case processor_t::ev_ana_insn:
      {
        insn_t *insn = va_arg(va, insn_t *);
        size_t length = ana(*insn);
        if (length) {
          insn->size = (uint16)length;
          return insn->size;       // event processed
        }
      }
      break;
    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const insn_t &insn = ctx->insn;
        if (insn.itype == S390X_unkn_1b) {
          int code1 = get_byte(insn.ea);
          char buf[9];
          qsnprintf(buf, sizeof(buf), "unsup_%02x", code1);
          ctx->out_line(buf, COLOR_INSN);
        } else if (insn.itype == S390X_unkn_2b) {
          int code1 = get_byte(insn.ea);
          int code2 = get_byte(insn.ea+1);
          char buf[11];
          qsnprintf(buf, sizeof(buf), "unsup_%04x", code1 << 8 | code2);
          ctx->out_line(buf, COLOR_INSN);
        } else if (insn.itype > S390X_unkn_2b) {
          ctx->out_line(get_insn_mnem(insn), COLOR_INSN);
          return 1;
        }
      }
      break;
  }
  return 0;                     // event is not processed
}

//--------------------------------------------------------------------------
// Initialize the plugin.
// IDA will call this function only once.
// If this function returns PLUGIN_SKIP, IDA will unload the plugin.
// Otherwise the plugin returns a pointer to a newly created context structure.

static size_t idaapi init() {
  processor_t &ph = PH;
  if (ph.id != PLFM_S390)
    return PLUGIN_SKIP;
  return size_t(new plugin_ctx_t);
}

//-------------------------------------------------------------------------
plugin_ctx_t::plugin_ctx_t() : plugmod_t(PLUGIN) {
  s390x_node.create(node_name);
  hooked = s390x_node.altval(0) != 0;
  if (hooked) {
    hook_event_listener(HT_IDP, this, this);
    msg("S390x processor extender is enabled\n");
  } else {
    msg("S390x processor extender is available for activation\n");
  }
}

//--------------------------------------------------------------------------
// Terminate the plugin.
// This destructor will be called before unloading the plugin.
plugin_ctx_t::~plugin_ctx_t() {
  // listeners are uninstalled automatically
  // when the owner module is unloaded
}

//--------------------------------------------------------------------------
// The plugin method
// This is the main function of plugin.
// It will be called when the user selects the plugin from the menu.
// The input argument is usually zero. Non-zero values can be specified
// by using load_and_run_plugin() or through plugins.cfg file (discouraged).
bool idaapi plugin_ctx_t::run(size_t) {
  if (hooked)
    unhook_event_listener(HT_IDP, this);
  else
    hook_event_listener(HT_IDP, this, this);
  hooked = !hooked;
  s390x_node.create(node_name);
  s390x_node.altset(0, hooked);
  info("AUTOHIDE NONE\n"
       "S390x processor extender now is %s", hooked ? "enabled" : "disabled");
  return true;
}

//--------------------------------------------------------------------------
static const char comment[] = "S390x processor extender";
static const char help[] = "Adds support for undocumented S390x instructions\n";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overridden in plugins.cfg file

static const char desired_name[] = "S390x processor extender";

// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overridden in plugins.cfg file

static const char desired_hotkey[] = "";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC           // this is a processor extension plugin
| PLUGIN_MULTI,         // this plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin. not used.
  help,                 // multiline help about the plugin. not used.
  desired_name,         // the preferred short name of the plugin
  desired_hotkey        // the preferred hotkey to run the plugin
};
