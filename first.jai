
#run,stallable build();
build :: () {
    set_build_options_dc(.{do_output=false});


    options := get_build_options();
    w := compiler_create_workspace("Main program");

    if !generate_chatger_protocol_bindings() then return;

    options.output_type            = .EXECUTABLE;
    options.output_executable_name = "main";
    set_build_options(options, w);

    compiler_begin_intercept(w);
    add_build_file("main.jai", w);
    compiler_end_intercept(w);
}

// TODO: Likely useless, will remove later
generate_chatger_protocol_bindings :: () -> bool {

    if file_exists("./protocol.jai") then return true;

    using opts: Generate_Bindings_Options;
    output_filename := "protocol.jai";
    array_add(*source_files, "./protocol.h");

    if !generate_bindings(opts, output_filename) {
        print("[ERROR]: Failed to generated protocol.h bindings\n");
        compiler_set_workspace_status(.FAILED);
        return false;
    }

    return true;
}

#import "Compiler";
#import "Basic";
#import "File_Utilities";
#import "Bindings_Generator";
