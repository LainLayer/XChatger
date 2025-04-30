

#import "X11";

FILE :: *void;
XrmOptionDescRec :: void;
#load "generated.jai";

Box_Type          :: FL_BOX_TYPE;
Input_Type        :: FL_INPUT_TYPE;
Button_Type       :: FL_BUTTON_TYPE;
Form              :: FL_FORM;
Object            :: FL_OBJECT;
Gravity_Direction :: FL_7;
Placement         :: FL_PLACE;
Border_Type       :: FL_1;
Tab_Folder_Type   :: FL_20;

do_forms :: fl_do_forms;

initialize :: inline () {
    global_context = *context;
    fl_initialize(xx *__command_line_arguments.count, __command_line_arguments.data, null, null, 0);
}

begin_form :: inline (type: Box_Type, w: s32, h: s32) -> *Form { return fl_bgn_form(xx type, w, h); }
end_form :: fl_end_form;

add_button :: inline (type: Button_Type, x: s32, y: s32, w: s32, h: s32, label: string = "") -> *Object {
    return fl_add_button(xx type, x, y, w, h, temp_c_string(label));
}

add_input :: inline (type: Input_Type, x: s32, y: s32, w: s32, h: s32, label: string = "") -> *Object {
    return fl_add_input(xx type, x, y, w, h, temp_c_string(label));
}

set_callback :: inline (object: *Object, $callback: (object: *Object, data: s64), argument: s64 = 0) {

    inner_callback :: inline (object: *Object, data: s64) #c_call {
        push_context global_context.* {
            callback(object, data);
        }
    }

    fl_set_object_callback(object, inner_callback, argument);
}

set_gravity :: inline (object: *Object, gravity1: Gravity_Direction, gravity2: Gravity_Direction) {
    fl_set_object_gravity(object, xx gravity1, xx gravity2);
}

set_input :: inline (object: *Object, value: string) {
    fl_set_input(object, temp_c_string(value));
}

show_form :: inline (form: *Form, place: Placement, border: Border_Type, name: string) -> Window {
    return fl_show_form(form, xx place, xx border, temp_c_string(name));
}
hide_form :: fl_hide_form;

add_bitmap :: inline (x: s32, y: s32, w: s32, h: s32, label := "") -> *Object {
    // There is apparently only one type of bitmap.
    return fl_add_bitmap(FL_NORMAL_BITMAP, x, y, w, h, temp_c_string(label));
}

// When X11 says "bitmap" is means the ".xbm" image format, not a .bpm or raw image.
// - https://en.wikipedia.org/wiki/X_BitMap
set_bitmap_file :: inline (bitmap: *Object, filename: string) {
    fl_set_bitmap_file(bitmap, temp_c_string(filename));
}

add_text :: inline (x: s32, y: s32, w: s32, h: s32, label: string) -> *Object {
    return fl_add_text(0, x, y, w, h, temp_c_string(label));
}

get_input :: inline (object: *Object) -> string {
    result: string;
    result.data  = fl_get_input(object);
    result.count = c_style_strlen(result.data);
    return result;
}

add_tab_folder :: inline (type: Tab_Folder_Type, x: s32, y: s32, w: s32, h: s32, label: string) -> *Object {
    return fl_add_tabfolder(xx type, x, y, w, h, temp_c_string(label));
}

add_form_as_tab :: inline (folder: *Object, label: string, form: *Form) -> *Object {
    return fl_addto_tabfolder(folder, temp_c_string(label), form);
}


#scope_file

X11 :: #library,system,link_always "X11";
Xpm :: #library,system,link_always "Xpm";
M   :: #library,system,link_always "m";
global_context: *#Context;
