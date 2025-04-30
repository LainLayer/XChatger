UNIT_NAMES :: #run -> []string {

    base_names :: string.[
        "align",         "appwin",        "asyn_io",           "bitmap",       "box",
        "browser",       "button",        "canvas",            "chart",        "checkbut",
        "child",         "choice",        "clipboard",         "clock",        "cmd_br",
        "colsel",        "combo",         "counter",           "cursor",       "dial",
        "display",       "errmsg",        "events",            "flcolor",      "fldraw",
        "flresource",    "flsnprintf",    "flvisual",          "fonts",        "formbrowser",
        "forms",         "frame",         "free",              "fselect",      "global",
        "goodie_alert",  "goodie_choice", "goodie_colchooser", "goodie_input", "goodie_msg",
        "goodie_sinput", "goodies",       "goodie_yesno",      "handling",     "input",
        "interpol",      "keyboard",      "labelbut",          "lframe",       //"libforms",
        "lightbut",      "listdir",       "menu",              "nmenu",        "objects",
        "oneliner",      "pixmap",        "popup",             "positioner",   "read2lsbf",
        "read2msbf",     "read4lsb",      "read4msb",          "readint",      "round3d",
        "roundbut",      "scrollbar",     "scrollbut",         "select",       "signal",
        "sldraw",        "slider",        "space",             "spinner",      "strdup",
        "symbols",       "sysdep",        "tabfolder",         "tbox",         "text",
        "thumbwheel",    "timeout",       "timer",             "tooltip",      "util",
        "valuator",      "version",       "vn_pair",           "win",          "xdraw",
        "xpopup",        "xsupport",      "xtext",             "xyplot",
    ];

    result: [..]string;

    for base_names array_add(*result, sprint("xforms-1.2.5pre1/lib/%.c", it));

    return result;
}

#run,stallable generate();
generate :: () {
    set_build_options_dc(.{do_output=false});

    options := get_build_options();

    FORMS_HEADER :: "xforms-1.2.5pre1/lib/include/forms.h";

    success := build_cpp_static_lib(
        "libforms",
        ..UNIT_NAMES,
        debug=true,
        extra = .[
            "-w",
            "-pipe",
            "-I./xforms-1.2.5pre1/lib/",
            "-I.",
            "-DMAKING_FORMS",
            "-DFL_EXPORT=extern",
            "-std=c89",
            "-DHAVE_CONFIG_H"
        ]
    );

    if !success {
        print("[ERROR]: Building xforms failed\n");
        compiler_set_workspace_status(.FAILED);
        return;
    }

    {
        using opts: Generate_Bindings_Options;
        output_filename := "generated.jai";
        array_add(*libpaths,      "./");
        array_add(*libnames,      "libforms");
        array_add(*source_files,  FORMS_HEADER);

        if !generate_bindings(opts, output_filename) {
            print("[ERROR]: Failed to generated XForms bindings\n");
            compiler_set_workspace_status(.FAILED);
            return;
        }
    }
}

#import "Bindings_Generator";
#import "Compiler";
#import "Basic";
#import "BuildCpp";
#import "File_Utilities";
#import "File";
