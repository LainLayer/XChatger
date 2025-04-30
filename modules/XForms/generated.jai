//
// This file was auto-generated using the following command:
//
// jai generate.jai
//



FL_VERSION :: 1;
FL_REVISION :: 2;
FL_FIXLEVEL :: "5pre1";
FL_INCLUDE_VERSION :: FL_VERSION * 1000 + FL_REVISION;

FL_COORD :: FL_Coord;

FL_BEGIN_GROUP :: 10000;
FL_END_GROUP :: 20000;

FL_USER_CLASS_START :: 1001;
FL_USER_CLASS_END :: 9999;

FL_MAX_BW :: 10;

FL_RETURN_NONE :: 0;
FL_RETURN_CHANGED :: 1;
FL_RETURN_END :: 2;
FL_RETURN_END_CHANGED :: 4;
FL_RETURN_SELECTION :: 8;
FL_RETURN_DESELECTION :: 16;
FL_RETURN_TRIGGERED :: 1024;
FL_RETURN_ALWAYS :: ~ FL_RETURN_END_CHANGED;

FL_ALT_MASK :: 1 << 25;
FL_CONTROL_MASK :: 1 << 26;
FL_SHIFT_MASK :: 1 << 27;
FL_ALT_VAL :: FL_ALT_MASK;

MAX_SHORTCUTS :: 8;

FL_MENU_ENTRY :: FL_PUP_ENTRY;

FL_MAXFONTS :: 48;

FL_FONT_STYLE :: FL_TEXT_STYLE;

FL_TINY_SIZE :: 8;
FL_SMALL_SIZE :: 10;
FL_NORMAL_SIZE :: 12;
FL_MEDIUM_SIZE :: 14;
FL_LARGE_SIZE :: 18;
FL_HUGE_SIZE :: 24;

FL_DEFAULT_SIZE :: FL_SMALL_SIZE;

FL_TINY_FONT :: FL_TINY_SIZE;
FL_SMALL_FONT :: FL_SMALL_SIZE;
FL_NORMAL_FONT :: FL_NORMAL_SIZE;
FL_MEDIUM_FONT :: FL_MEDIUM_SIZE;
FL_LARGE_FONT :: FL_LARGE_SIZE;
FL_HUGE_FONT :: FL_HUGE_SIZE;

FL_NORMAL_FONT1 :: FL_SMALL_FONT;
FL_NORMAL_FONT2 :: FL_NORMAL_FONT;
FL_DEFAULT_FONT :: FL_SMALL_FONT;

FL_BOUND_WIDTH :: cast(FL_Coord) 1;

FL_CLICK_TIMEOUT :: 400;

fl_set_object_focus :: fl_set_focus_object;

fl_set_form_call_back :: fl_set_form_callback;

fl_set_initial_placement :: fl_set_form_geometry;

fl_register_call_back :: fl_register_raw_callback;

fl_draw_object_outside_label :: fl_draw_object_label_outside;

fl_set_object_lcolor :: fl_set_object_lcol;
fl_get_object_lcolor :: fl_get_object_lcol;

fl_compute_object_geometry :: fl_get_object_bbox;

fl_set_object_align :: fl_set_object_lalign;
fl_set_call_back :: fl_set_object_callback;

fl_get_string_size :: fl_get_string_dimension;

fl_drw_text :: fl_draw_text;

fl_drw_text_beside :: fl_draw_text_beside;

fl_drw_text_cursor :: fl_draw_text_cursor;

fl_drw_box :: fl_draw_box;

fl_mapcolor_name :: fl_mapcolorname;

fl_get_flcolor :: fl_get_pixel;

fl_set_error_logfp :: fl_set_err_logfp;

fl_mousebutton :: fl_mouse_button;

FL_MAX_MENU_CHOICE_ITEMS :: 128;

FL_MINDEPTH :: 1;

FL_MAX_COLORS :: 1024;
FL_MAX_COLS :: FL_MAX_COLORS;

FL_STATE :: FL_State;

FL_MAX_FONTSIZES :: 10;
FL_MAX_FONTNAME_LENGTH :: 80;

fl_simple_line :: fl_line;

fl_set_linewidth :: fl_linewidth;
fl_set_linestyle :: fl_linestyle;
fl_set_drawmode :: fl_drawmode;

fl_oval_bound :: fl_ovalbound;

fl_drw_frame :: fl_draw_frame;

fl_get_font_struct :: fl_get_fontstruct;
fl_get_fntstruct :: fl_get_font_struct;

fl_pref_winposition :: fl_winposition;
fl_win_background :: fl_winbackground;
fl_winstepunit :: fl_winstepsize;
fl_set_winstepunit :: fl_winstepsize;

fl_pref_winsize :: fl_winsize;

fl_pref_wingeometry :: fl_wingeometry;

fl_get_win_size :: fl_get_winsize;
fl_get_win_origin :: fl_get_winorigin;
fl_get_win_geometry :: fl_get_wingeometry;
fl_initial_winposition :: fl_pref_winposition;

fl_add_selected_xevent :: fl_addto_selected_xevent;

fl_keypressed :: fl_keysym_pressed;

FL_resource :: FL_RESOURCE;

FL_PCBITS :: 8;
FL_PCMAX :: ( 1 << FL_PCBITS ) - 1;

FL_PACKED :: FL_PACKED4;

FL_RMASK :: 0x000000ff;
FL_RSHIFT :: 0;
FL_GMASK :: 0x0000ff00;
FL_GSHIFT :: 8;
FL_BMASK :: 0x00ff0000;
FL_BSHIFT :: 16;
FL_AMASK :: 0xff000000;
FL_ASHIFT :: 24;

FL_RGB2PIXEL :: FL_RGB2PIXEL_;

FL_NORMAL_BITMAP :: 0;

fl_set_bitmap_datafile :: fl_set_bitmap_file;

FL_NORMAL_PIXMAP :: 0;

FL_BROWSER_FONTSIZE :: FL_SMALL_SIZE;

FL_BROWSER_LINELENGTH :: 2048;

fl_append_browser :: fl_addto_browser_chars;

fl_append_browser_f :: fl_addto_browser_chars_f;

FL_BUTTON_STRUCT :: FL_BUTTON_SPEC;

FL_DRAWBUTTON :: FL_DrawButton;
FL_CLEANUPBUTTON :: FL_CleanupButton;

FL_BUTTON_BW :: FL_BOUND_WIDTH;

FL_LIGHTBUTTON_MINSIZE :: cast(FL_Coord) 12;

fl_set_bitmapbutton_file :: fl_set_bitmap_file;

fl_set_bitmapbutton_datafile :: fl_set_bitmapbutton_file;

fl_set_pixmapbutton_data :: fl_set_pixmap_data;
fl_set_pixmapbutton_file :: fl_set_pixmap_file;
fl_set_pixmapbutton_pixmap :: fl_set_pixmap_pixmap;
fl_get_pixmapbutton_pixmap :: fl_get_pixmap_pixmap;
fl_set_pixmapbutton_align :: fl_set_pixmap_align;
fl_free_pixmapbutton_pixmap :: fl_free_pixmap_pixmap;
fl_set_pixmapbutton_datafile :: fl_set_pixmapbutton_file;
fl_set_pixmapbutton_show_focus :: fl_set_pixmapbutton_focus_outline;

fl_set_button_shortcut :: fl_set_object_shortcut;

fl_set_canvas_decoration :: fl_set_object_boxtype;

FL_CHART_MAX :: 2048;

fl_set_chart_lcol :: fl_set_chart_lcolor;

FL_CHOICE_MAXITEMS :: 128;

FL_SELECTION_CALLBACK :: FL_SELECTION_CB;
FL_LOSE_SELECTION_CALLBACK :: FL_LOSE_SELECTION_CB;

FL_COUNTER_BW :: FL_BOUND_WIDTH;

fl_set_dial_crossover :: fl_set_dial_cross;

fl_get_formbrowser_forms :: fl_get_formbrowser_numforms;

FLAlertDismissLabel :: "flAlert.dismiss.label";
FLAlertTitle :: "flAlert.title";

FLQuestionYesLabel :: "flQuestion.yes.label";
FLQuestionNoLabel :: "flQuestion.no.label";
FLQuestionTitle :: "flQuestion.title";

FLOKLabel :: "flInput.ok.label";
FLInputClearLabel :: "flInput.clear.label";
FLInputCancelLabel :: "flInput.cancel.label";
FLInputTitle :: "flInput.title";

FLChoiceTitle :: "flChoice.title";

fl_show_msg :: fl_show_messages_f;

fl_hide_msg :: fl_hide_message;
fl_hide_messages :: fl_hide_message;

fl_show_alert2 :: fl_show_alert_f;

fl_set_choice_shortcut :: fl_set_choices_shortcut;

fl_open_command :: fl_exe_command;
fl_close_command :: fl_end_command;

FL_MAX_FSELECTOR :: 6;

fl_show_file_selector :: fl_show_fselector;
fl_set_fselector_cb :: fl_set_fselector_callback;

FL_RINGBELL :: 1 << 4;

FL_INPUTVALIDATOR :: FL_INPUT_VALIDATOR;

fl_set_input_shortcut :: fl_set_object_shortcut;

FL_MENU_MAXITEMS :: 128;
FL_MENU_MAXSTR :: 64;

FL_NORMAL_POSITIONER :: 0;
FL_OVERLAY_POSITIONER :: 1;
FL_INVISIBLE_POSITIONER :: 2;

FL_POSITIONER_INVALID :: 0;
FL_POSITIONER_VALID :: 1;
FL_POSITIONER_REPLACED :: 2;

FL_HOR_FLAG :: 1;
FL_SCROLL_FLAG :: 16;

FL_SLIDER_BW1 :: FL_BOUND_WIDTH;

FL_SLIDER_FINE :: 0.25;
FL_SLIDER_WIDTH :: 0.10;

FL_SLIDER_MAX_PREC :: 10;

FL_TIMER_BLINKRATE :: 0.2;

FL_MAXPUPI :: 128;
FL_PUP_PADH :: 4;

fl_setpup_fontsize :: fl_setpup_default_fontsize;
fl_setpup_fontstyle :: fl_setpup_default_fontstyle;
fl_setpup_color :: fl_setpup_default_color;
fl_setpup_default_checkcolor :: fl_setpup_default_pup_checked_color;
fl_setpup_checkcolor :: fl_setpup_default_pup_checked_color;

fl_setpup_hotkey :: fl_setpup_shortcut;

fl_setpup :: fl_setpup_mode;

FL_MAX_XYPLOTOVERLAY :: 32;

fl_set_xyplot_datafile :: fl_set_xyplot_file;

FL_FALSE :: 0;
FL_TRUE :: ! FL_FALSE;

/* Some general constants */
FL :: enum s32 {
    ON          :: 1;
    OK          :: 1;
    VALID       :: 1;
    PREEMPT     :: 1;
    AUTO        :: 2;
    WHEN_NEEDED :: 2;
    OFF         :: 0;
    CANCEL      :: 0;
    INVALID     :: 0;

    IGNORE      :: -1;

    FL_ON          :: ON;
    FL_OK          :: OK;
    FL_VALID       :: VALID;
    FL_PREEMPT     :: PREEMPT;
    FL_AUTO        :: AUTO;
    FL_WHEN_NEEDED :: WHEN_NEEDED;
    FL_OFF         :: OFF;
    FL_CANCEL      :: CANCEL;
    FL_INVALID     :: INVALID;

    FL_IGNORE      :: IGNORE;
}

/* The screen coordinate unit, FL_Coord, must be of signed type */
FL_Coord :: s32;

FL_COLOR :: u64;

/* Coordinates can be in pixels, milli-meters or points (1/72inch) */
FL_COORD_UNIT :: enum u32 {
    PIXEL      :: 0;
    MM         :: 1;
    POINT      :: 2;
    centiMM    :: 3;
    centiPOINT :: 4;

    FL_COORD_PIXEL      :: PIXEL;
    FL_COORD_MM         :: MM;
    FL_COORD_POINT      :: POINT;
    FL_COORD_centiMM    :: centiMM;
    FL_COORD_centiPOINT :: centiPOINT;
}

/* All object classes. */
FL_CLASS :: enum u32 {
    FL_INVALID_CLASS :: 0;
    FL_BUTTON        :: 1;
    FL_LIGHTBUTTON   :: 2;
    FL_ROUNDBUTTON   :: 3;
    FL_ROUND3DBUTTON :: 4;
    FL_CHECKBUTTON   :: 5;
    FL_BITMAPBUTTON  :: 6;
    FL_PIXMAPBUTTON  :: 7;
    FL_BITMAP        :: 8;
    FL_PIXMAP        :: 9;
    FL_BOX           :: 10;
    FL_TEXT          :: 11;
    FL_MENU          :: 12;
    FL_CHART         :: 13;
    FL_CHOICE        :: 14;
    FL_COUNTER       :: 15;
    FL_SLIDER        :: 16;
    FL_VALSLIDER     :: 17;
    FL_INPUT         :: 18;
    FL_BROWSER       :: 19;
    FL_DIAL          :: 20;
    FL_TIMER         :: 21;
    FL_CLOCK         :: 22;
    FL_POSITIONER    :: 23;
    FL_FREE          :: 24;
    FL_XYPLOT        :: 25;
    FL_FRAME         :: 26;
    FL_LABELFRAME    :: 27;
    FL_CANVAS        :: 28;
    FL_GLCANVAS      :: 29;
    FL_TABFOLDER     :: 30;
    FL_SCROLLBAR     :: 31;
    FL_SCROLLBUTTON  :: 32;
    FL_MENUBAR       :: 33;
    FL_TEXTBOX       :: 34;
    FL_LABELBUTTON   :: 35;
    FL_COMBOBOX      :: 36;
    FL_IMAGECANVAS   :: 37;
    FL_THUMBWHEEL    :: 38;
    FL_COLORWHEEL    :: 39;
    FL_FORMBROWSER   :: 40;
    FL_SELECT        :: 41;
    FL_NMENU         :: 42;
    FL_SPINNER       :: 43;
    FL_TBOX          :: 44;
    END              :: 45;
    FL_CLASS_END :: END;
}

/* How to display a form onto screen */
FL_PLACE :: enum u32 {
    FREE         :: 0;
    MOUSE        :: 1;
    CENTER       :: 2;
    POSITION     :: 4;
    SIZE         :: 8;
    GEOMETRY     :: 16;
    ASPECT       :: 32;
    FULLSCREEN   :: 64;
    HOTSPOT      :: 128;
    ICONIC       :: 256;

    FL_FREE_SIZE :: 16384;
    FL_FIX_SIZE  :: 32768;

    FL_PLACE_FREE       :: FREE;
    FL_PLACE_MOUSE      :: MOUSE;
    FL_PLACE_CENTER     :: CENTER;
    FL_PLACE_POSITION   :: POSITION;
    FL_PLACE_SIZE       :: SIZE;
    FL_PLACE_GEOMETRY   :: GEOMETRY;
    FL_PLACE_ASPECT     :: ASPECT;
    FL_PLACE_FULLSCREEN :: FULLSCREEN;
    FL_PLACE_HOTSPOT    :: HOTSPOT;
    FL_PLACE_ICONIC     :: ICONIC;
}

/* Window manager decoration request and forms attributes */
FL_1 :: enum u32 {
    FULLBORDER :: 1;
    TRANSIENT  :: 2;
    NOBORDER   :: 3;

    FL_FULLBORDER :: FULLBORDER;
    FL_TRANSIENT  :: TRANSIENT;
    FL_NOBORDER   :: NOBORDER;
}

/* All box types */
FL_BOX_TYPE :: enum u32 {
    NO_BOX                   :: 0;
    UP_BOX                   :: 1;
    DOWN_BOX                 :: 2;
    BORDER_BOX               :: 3;
    SHADOW_BOX               :: 4;
    FRAME_BOX                :: 5;
    ROUNDED_BOX              :: 6;
    EMBOSSED_BOX             :: 7;
    FLAT_BOX                 :: 8;
    RFLAT_BOX                :: 9;
    RSHADOW_BOX              :: 10;
    OVAL_BOX                 :: 11;
    ROUNDED3D_UPBOX          :: 12;
    ROUNDED3D_DOWNBOX        :: 13;
    OVAL3D_UPBOX             :: 14;
    OVAL3D_DOWNBOX           :: 15;
    OVAL3D_FRAMEBOX          :: 16;
    OVAL3D_EMBOSSEDBOX       :: 17;

    TOPTAB_UPBOX             :: 18;
    SELECTED_TOPTAB_UPBOX    :: 19;
    BOTTOMTAB_UPBOX          :: 20;
    SELECTED_BOTTOMTAB_UPBOX :: 21;

    MAX_BOX_STYLES           :: 22;

    FL_NO_BOX                   :: NO_BOX;
    FL_UP_BOX                   :: UP_BOX;
    FL_DOWN_BOX                 :: DOWN_BOX;
    FL_BORDER_BOX               :: BORDER_BOX;
    FL_SHADOW_BOX               :: SHADOW_BOX;
    FL_FRAME_BOX                :: FRAME_BOX;
    FL_ROUNDED_BOX              :: ROUNDED_BOX;
    FL_EMBOSSED_BOX             :: EMBOSSED_BOX;
    FL_FLAT_BOX                 :: FLAT_BOX;
    FL_RFLAT_BOX                :: RFLAT_BOX;
    FL_RSHADOW_BOX              :: RSHADOW_BOX;
    FL_OVAL_BOX                 :: OVAL_BOX;
    FL_ROUNDED3D_UPBOX          :: ROUNDED3D_UPBOX;
    FL_ROUNDED3D_DOWNBOX        :: ROUNDED3D_DOWNBOX;
    FL_OVAL3D_UPBOX             :: OVAL3D_UPBOX;
    FL_OVAL3D_DOWNBOX           :: OVAL3D_DOWNBOX;
    FL_OVAL3D_FRAMEBOX          :: OVAL3D_FRAMEBOX;
    FL_OVAL3D_EMBOSSEDBOX       :: OVAL3D_EMBOSSEDBOX;

    FL_TOPTAB_UPBOX             :: TOPTAB_UPBOX;
    FL_SELECTED_TOPTAB_UPBOX    :: SELECTED_TOPTAB_UPBOX;
    FL_BOTTOMTAB_UPBOX          :: BOTTOMTAB_UPBOX;
    FL_SELECTED_BOTTOMTAB_UPBOX :: SELECTED_BOTTOMTAB_UPBOX;

    FL_MAX_BOX_STYLES           :: MAX_BOX_STYLES;
}

/* How to place text relative to a box */
FL_ALIGN :: enum u32 {
    CENTER       :: 0;
    TOP          :: 1;
    BOTTOM       :: 2;
    LEFT         :: 4;
    RIGHT        :: 8;
    LEFT_TOP     :: 5;
    RIGHT_TOP    :: 9;
    LEFT_BOTTOM  :: 6;
    RIGHT_BOTTOM :: 10;
    INSIDE       :: 8192;
    VERT         :: 16384;

    TOP_LEFT     :: 5;
    TOP_RIGHT    :: 9;
    BOTTOM_LEFT  :: 6;
    BOTTOM_RIGHT :: 10;

    FL_ALIGN_CENTER       :: CENTER;
    FL_ALIGN_TOP          :: TOP;
    FL_ALIGN_BOTTOM       :: BOTTOM;
    FL_ALIGN_LEFT         :: LEFT;
    FL_ALIGN_RIGHT        :: RIGHT;
    FL_ALIGN_LEFT_TOP     :: LEFT_TOP;
    FL_ALIGN_RIGHT_TOP    :: RIGHT_TOP;
    FL_ALIGN_LEFT_BOTTOM  :: LEFT_BOTTOM;
    FL_ALIGN_RIGHT_BOTTOM :: RIGHT_BOTTOM;
    FL_ALIGN_INSIDE       :: INSIDE;
    FL_ALIGN_VERT         :: VERT;

    FL_ALIGN_TOP_LEFT     :: TOP_LEFT;
    FL_ALIGN_TOP_RIGHT    :: TOP_RIGHT;
    FL_ALIGN_BOTTOM_LEFT  :: BOTTOM_LEFT;
    FL_ALIGN_BOTTOM_RIGHT :: BOTTOM_RIGHT;
}

fl_is_inside_lalign :: (align: s32) -> s32 #foreign libforms;

fl_is_outside_lalign :: (align: s32) -> s32 #foreign libforms;

fl_is_center_lalign :: (align: s32) -> s32 #foreign libforms;

fl_to_inside_lalign :: (align: s32) -> s32 #foreign libforms;

fl_to_outside_lalign :: (align: s32) -> s32 #foreign libforms;

/* Mouse buttons */
FL_2 :: enum u32 {
    MBUTTON1 :: 1;
    MBUTTON2 :: 2;
    MBUTTON3 :: 3;
    MBUTTON4 :: 4;
    MBUTTON5 :: 5;

    FL_MBUTTON1 :: MBUTTON1;
    FL_MBUTTON2 :: MBUTTON2;
    FL_MBUTTON3 :: MBUTTON3;
    FL_MBUTTON4 :: MBUTTON4;
    FL_MBUTTON5 :: MBUTTON5;
}

/*  Some special color indices for FL private colormap. It does not matter
*  what the value of each enum is, but it must start from 0 and be
*  consecutive. */
FL_PD_COL :: enum u32 {
    BLACK                :: 0;
    RED                  :: 1;
    GREEN                :: 2;
    YELLOW               :: 3;
    BLUE                 :: 4;
    MAGENTA              :: 5;
    CYAN                 :: 6;
    WHITE                :: 7;
    TOMATO               :: 8;
    INDIANRED            :: 9;
    SLATEBLUE            :: 10;
    COL1                 :: 11;
    RIGHT_BCOL           :: 12;
    BOTTOM_BCOL          :: 13;
    TOP_BCOL             :: 14;
    LEFT_BCOL            :: 15;
    MCOL                 :: 16;
    INACTIVE             :: 17;
    PALEGREEN            :: 18;
    DARKGOLD             :: 19;
    ORCHID               :: 20;
    DARKCYAN             :: 21;
    DARKTOMATO           :: 22;
    WHEAT                :: 23;
    DARKORANGE           :: 24;
    DEEPPINK             :: 25;
    CHARTREUSE           :: 26;
    DARKVIOLET           :: 27;
    SPRINGGREEN          :: 28;
    DODGERBLUE           :: 29;
    LIGHTER_COL1         :: 30;
    DARKER_COL1          :: 31;
    ALICEBLUE            :: 32;
    ANTIQUEWHITE         :: 33;
    AQUA                 :: 34;
    AQUAMARINE           :: 35;
    AZURE                :: 36;
    BEIGE                :: 37;
    BISQUE               :: 38;
    BLANCHEDALMOND       :: 39;
    BLUEVIOLET           :: 40;
    BROWN                :: 41;
    BURLYWOOD            :: 42;
    CADETBLUE            :: 43;
    CHOCOLATE            :: 44;
    CORAL                :: 45;
    CORNFLOWERBLUE       :: 46;
    CORNSILK             :: 47;
    CRIMSON              :: 48;
    DARKBLUE             :: 49;
    DARKGOLDENROD        :: 50;
    DARKGRAY             :: 51;
    DARKGREEN            :: 52;
    DARKGREY             :: 53;
    DARKKHAKI            :: 54;
    DARKMAGENTA          :: 55;
    DARKOLIVEGREEN       :: 56;
    DARKORCHID           :: 57;
    DARKRED              :: 58;
    DARKSALMON           :: 59;
    DARKSEAGREEN         :: 60;
    DARKSLATEBLUE        :: 61;
    DARKSLATEGRAY        :: 62;
    DARKSLATEGREY        :: 63;
    DARKTURQUOISE        :: 64;
    DEEPSKYBLUE          :: 65;
    DIMGRAY              :: 66;
    DIMGREY              :: 67;
    FIREBRICK            :: 68;
    FLORALWHITE          :: 69;
    FORESTGREEN          :: 70;
    FUCHSIA              :: 71;
    GAINSBORO            :: 72;
    GHOSTWHITE           :: 73;
    GOLD                 :: 74;
    GOLDENROD            :: 75;
    GRAY                 :: 76;
    GREENYELLOW          :: 77;
    GREY                 :: 78;
    HONEYDEW             :: 79;
    HOTPINK              :: 80;
    INDIGO               :: 81;
    IVORY                :: 82;
    KHAKI                :: 83;
    LAVENDER             :: 84;
    LAVENDERBLUSH        :: 85;
    LAWNGREEN            :: 86;
    LEMONCHIFFON         :: 87;
    LIGHTBLUE            :: 88;
    LIGHTCORAL           :: 89;
    LIGHTCYAN            :: 90;
    LIGHTGOLDENRODYELLOW :: 91;
    LIGHTGRAY            :: 92;
    LIGHTGREEN           :: 93;
    LIGHTGREY            :: 94;
    LIGHTPINK            :: 95;
    LIGHTSALMON          :: 96;
    LIGHTSEAGREEN        :: 97;
    LIGHTSKYBLUE         :: 98;
    LIGHTSLATEGRAY       :: 99;
    LIGHTSLATEGREY       :: 100;
    LIGHTSTEELBLUE       :: 101;
    LIGHTYELLOW          :: 102;
    LIME                 :: 103;
    LIMEGREEN            :: 104;
    LINEN                :: 105;
    MAROON               :: 106;
    MEDIUMAQUAMARINE     :: 107;
    MEDIUMBLUE           :: 108;
    MEDIUMORCHID         :: 109;
    MEDIUMPURPLE         :: 110;
    MEDIUMSEAGREEN       :: 111;
    MEDIUMSLATEBLUE      :: 112;
    MEDIUMSPRINGGREEN    :: 113;
    MEDIUMTURQUOISE      :: 114;
    MEDIUMVIOLETRED      :: 115;
    MIDNIGHTBLUE         :: 116;
    MINTCREAM            :: 117;
    MISTYROSE            :: 118;
    MOCCASIN             :: 119;
    NAVAJOWHITE          :: 120;
    NAVY                 :: 121;
    OLDLACE              :: 122;
    OLIVE                :: 123;
    OLIVEDRAB            :: 124;
    ORANGE               :: 125;
    ORANGERED            :: 126;
    PALEGOLDENROD        :: 127;
    PALETURQUOISE        :: 128;
    PALEVIOLETRED        :: 129;
    PAPAYAWHIP           :: 130;
    PEACHPUFF            :: 131;
    PERU                 :: 132;
    PINK                 :: 133;
    PLUM                 :: 134;
    POWDERBLUE           :: 135;
    PURPLE               :: 136;
    ROSYBROWN            :: 137;
    ROYALBLUE            :: 138;
    SADDLEBROWN          :: 139;
    SALMON               :: 140;
    SANDYBROWN           :: 141;
    SEAGREEN             :: 142;
    SEASHELL             :: 143;
    SIENNA               :: 144;
    SILVER               :: 145;
    SKYBLUE              :: 146;
    SLATEGRAY            :: 147;
    SLATEGREY            :: 148;
    SNOW                 :: 149;
    STEELBLUE            :: 150;
    TAN                  :: 151;
    TEAL                 :: 152;
    THISTLE              :: 153;
    TURQUOISE            :: 154;
    VIOLET               :: 155;
    WHITESMOKE           :: 156;
    YELLOWGREEN          :: 157;
    COLOR_CHOOSER_COLOR  :: 158;
    FREE_COL1            :: 159;
    FREE_COL2            :: 160;
    FREE_COL3            :: 161;
    FREE_COL4            :: 162;
    FREE_COL5            :: 163;
    FREE_COL6            :: 164;
    FREE_COL7            :: 165;
    FREE_COL8            :: 166;
    FREE_COL9            :: 167;
    FREE_COL10           :: 168;
    FREE_COL11           :: 169;
    FREE_COL12           :: 170;
    FREE_COL13           :: 171;
    FREE_COL14           :: 172;
    FREE_COL15           :: 173;
    FREE_COL16           :: 174;
    NOCOLOR              :: 2147483647;

    FL_BLACK                :: BLACK;
    FL_RED                  :: RED;
    FL_GREEN                :: GREEN;
    FL_YELLOW               :: YELLOW;
    FL_BLUE                 :: BLUE;
    FL_MAGENTA              :: MAGENTA;
    FL_CYAN                 :: CYAN;
    FL_WHITE                :: WHITE;
    FL_TOMATO               :: TOMATO;
    FL_INDIANRED            :: INDIANRED;
    FL_SLATEBLUE            :: SLATEBLUE;
    FL_COL1                 :: COL1;
    FL_RIGHT_BCOL           :: RIGHT_BCOL;
    FL_BOTTOM_BCOL          :: BOTTOM_BCOL;
    FL_TOP_BCOL             :: TOP_BCOL;
    FL_LEFT_BCOL            :: LEFT_BCOL;
    FL_MCOL                 :: MCOL;
    FL_INACTIVE             :: INACTIVE;
    FL_PALEGREEN            :: PALEGREEN;
    FL_DARKGOLD             :: DARKGOLD;
    FL_ORCHID               :: ORCHID;
    FL_DARKCYAN             :: DARKCYAN;
    FL_DARKTOMATO           :: DARKTOMATO;
    FL_WHEAT                :: WHEAT;
    FL_DARKORANGE           :: DARKORANGE;
    FL_DEEPPINK             :: DEEPPINK;
    FL_CHARTREUSE           :: CHARTREUSE;
    FL_DARKVIOLET           :: DARKVIOLET;
    FL_SPRINGGREEN          :: SPRINGGREEN;
    FL_DODGERBLUE           :: DODGERBLUE;
    FL_LIGHTER_COL1         :: LIGHTER_COL1;
    FL_DARKER_COL1          :: DARKER_COL1;
    FL_ALICEBLUE            :: ALICEBLUE;
    FL_ANTIQUEWHITE         :: ANTIQUEWHITE;
    FL_AQUA                 :: AQUA;
    FL_AQUAMARINE           :: AQUAMARINE;
    FL_AZURE                :: AZURE;
    FL_BEIGE                :: BEIGE;
    FL_BISQUE               :: BISQUE;
    FL_BLANCHEDALMOND       :: BLANCHEDALMOND;
    FL_BLUEVIOLET           :: BLUEVIOLET;
    FL_BROWN                :: BROWN;
    FL_BURLYWOOD            :: BURLYWOOD;
    FL_CADETBLUE            :: CADETBLUE;
    FL_CHOCOLATE            :: CHOCOLATE;
    FL_CORAL                :: CORAL;
    FL_CORNFLOWERBLUE       :: CORNFLOWERBLUE;
    FL_CORNSILK             :: CORNSILK;
    FL_CRIMSON              :: CRIMSON;
    FL_DARKBLUE             :: DARKBLUE;
    FL_DARKGOLDENROD        :: DARKGOLDENROD;
    FL_DARKGRAY             :: DARKGRAY;
    FL_DARKGREEN            :: DARKGREEN;
    FL_DARKGREY             :: DARKGREY;
    FL_DARKKHAKI            :: DARKKHAKI;
    FL_DARKMAGENTA          :: DARKMAGENTA;
    FL_DARKOLIVEGREEN       :: DARKOLIVEGREEN;
    FL_DARKORCHID           :: DARKORCHID;
    FL_DARKRED              :: DARKRED;
    FL_DARKSALMON           :: DARKSALMON;
    FL_DARKSEAGREEN         :: DARKSEAGREEN;
    FL_DARKSLATEBLUE        :: DARKSLATEBLUE;
    FL_DARKSLATEGRAY        :: DARKSLATEGRAY;
    FL_DARKSLATEGREY        :: DARKSLATEGREY;
    FL_DARKTURQUOISE        :: DARKTURQUOISE;
    FL_DEEPSKYBLUE          :: DEEPSKYBLUE;
    FL_DIMGRAY              :: DIMGRAY;
    FL_DIMGREY              :: DIMGREY;
    FL_FIREBRICK            :: FIREBRICK;
    FL_FLORALWHITE          :: FLORALWHITE;
    FL_FORESTGREEN          :: FORESTGREEN;
    FL_FUCHSIA              :: FUCHSIA;
    FL_GAINSBORO            :: GAINSBORO;
    FL_GHOSTWHITE           :: GHOSTWHITE;
    FL_GOLD                 :: GOLD;
    FL_GOLDENROD            :: GOLDENROD;
    FL_GRAY                 :: GRAY;
    FL_GREENYELLOW          :: GREENYELLOW;
    FL_GREY                 :: GREY;
    FL_HONEYDEW             :: HONEYDEW;
    FL_HOTPINK              :: HOTPINK;
    FL_INDIGO               :: INDIGO;
    FL_IVORY                :: IVORY;
    FL_KHAKI                :: KHAKI;
    FL_LAVENDER             :: LAVENDER;
    FL_LAVENDERBLUSH        :: LAVENDERBLUSH;
    FL_LAWNGREEN            :: LAWNGREEN;
    FL_LEMONCHIFFON         :: LEMONCHIFFON;
    FL_LIGHTBLUE            :: LIGHTBLUE;
    FL_LIGHTCORAL           :: LIGHTCORAL;
    FL_LIGHTCYAN            :: LIGHTCYAN;
    FL_LIGHTGOLDENRODYELLOW :: LIGHTGOLDENRODYELLOW;
    FL_LIGHTGRAY            :: LIGHTGRAY;
    FL_LIGHTGREEN           :: LIGHTGREEN;
    FL_LIGHTGREY            :: LIGHTGREY;
    FL_LIGHTPINK            :: LIGHTPINK;
    FL_LIGHTSALMON          :: LIGHTSALMON;
    FL_LIGHTSEAGREEN        :: LIGHTSEAGREEN;
    FL_LIGHTSKYBLUE         :: LIGHTSKYBLUE;
    FL_LIGHTSLATEGRAY       :: LIGHTSLATEGRAY;
    FL_LIGHTSLATEGREY       :: LIGHTSLATEGREY;
    FL_LIGHTSTEELBLUE       :: LIGHTSTEELBLUE;
    FL_LIGHTYELLOW          :: LIGHTYELLOW;
    FL_LIME                 :: LIME;
    FL_LIMEGREEN            :: LIMEGREEN;
    FL_LINEN                :: LINEN;
    FL_MAROON               :: MAROON;
    FL_MEDIUMAQUAMARINE     :: MEDIUMAQUAMARINE;
    FL_MEDIUMBLUE           :: MEDIUMBLUE;
    FL_MEDIUMORCHID         :: MEDIUMORCHID;
    FL_MEDIUMPURPLE         :: MEDIUMPURPLE;
    FL_MEDIUMSEAGREEN       :: MEDIUMSEAGREEN;
    FL_MEDIUMSLATEBLUE      :: MEDIUMSLATEBLUE;
    FL_MEDIUMSPRINGGREEN    :: MEDIUMSPRINGGREEN;
    FL_MEDIUMTURQUOISE      :: MEDIUMTURQUOISE;
    FL_MEDIUMVIOLETRED      :: MEDIUMVIOLETRED;
    FL_MIDNIGHTBLUE         :: MIDNIGHTBLUE;
    FL_MINTCREAM            :: MINTCREAM;
    FL_MISTYROSE            :: MISTYROSE;
    FL_MOCCASIN             :: MOCCASIN;
    FL_NAVAJOWHITE          :: NAVAJOWHITE;
    FL_NAVY                 :: NAVY;
    FL_OLDLACE              :: OLDLACE;
    FL_OLIVE                :: OLIVE;
    FL_OLIVEDRAB            :: OLIVEDRAB;
    FL_ORANGE               :: ORANGE;
    FL_ORANGERED            :: ORANGERED;
    FL_PALEGOLDENROD        :: PALEGOLDENROD;
    FL_PALETURQUOISE        :: PALETURQUOISE;
    FL_PALEVIOLETRED        :: PALEVIOLETRED;
    FL_PAPAYAWHIP           :: PAPAYAWHIP;
    FL_PEACHPUFF            :: PEACHPUFF;
    FL_PERU                 :: PERU;
    FL_PINK                 :: PINK;
    FL_PLUM                 :: PLUM;
    FL_POWDERBLUE           :: POWDERBLUE;
    FL_PURPLE               :: PURPLE;
    FL_ROSYBROWN            :: ROSYBROWN;
    FL_ROYALBLUE            :: ROYALBLUE;
    FL_SADDLEBROWN          :: SADDLEBROWN;
    FL_SALMON               :: SALMON;
    FL_SANDYBROWN           :: SANDYBROWN;
    FL_SEAGREEN             :: SEAGREEN;
    FL_SEASHELL             :: SEASHELL;
    FL_SIENNA               :: SIENNA;
    FL_SILVER               :: SILVER;
    FL_SKYBLUE              :: SKYBLUE;
    FL_SLATEGRAY            :: SLATEGRAY;
    FL_SLATEGREY            :: SLATEGREY;
    FL_SNOW                 :: SNOW;
    FL_STEELBLUE            :: STEELBLUE;
    FL_TAN                  :: TAN;
    FL_TEAL                 :: TEAL;
    FL_THISTLE              :: THISTLE;
    FL_TURQUOISE            :: TURQUOISE;
    FL_VIOLET               :: VIOLET;
    FL_WHITESMOKE           :: WHITESMOKE;
    FL_YELLOWGREEN          :: YELLOWGREEN;
    FL_COLOR_CHOOSER_COLOR  :: COLOR_CHOOSER_COLOR;
    FL_FREE_COL1            :: FREE_COL1;
    FL_FREE_COL2            :: FREE_COL2;
    FL_FREE_COL3            :: FREE_COL3;
    FL_FREE_COL4            :: FREE_COL4;
    FL_FREE_COL5            :: FREE_COL5;
    FL_FREE_COL6            :: FREE_COL6;
    FL_FREE_COL7            :: FREE_COL7;
    FL_FREE_COL8            :: FREE_COL8;
    FL_FREE_COL9            :: FREE_COL9;
    FL_FREE_COL10           :: FREE_COL10;
    FL_FREE_COL11           :: FREE_COL11;
    FL_FREE_COL12           :: FREE_COL12;
    FL_FREE_COL13           :: FREE_COL13;
    FL_FREE_COL14           :: FREE_COL14;
    FL_FREE_COL15           :: FREE_COL15;
    FL_FREE_COL16           :: FREE_COL16;
    FL_NOCOLOR              :: NOCOLOR;
}

/* Events that a form reacts to  */
FL_EVENTS :: enum u32 {
    NOEVENT    :: 0;
    DRAW       :: 1;
    PUSH       :: 2;
    RELEASE    :: 3;
    ENTER      :: 4;
    LEAVE      :: 5;
    MOTION     :: 6;
    FOCUS      :: 7;
    UNFOCUS    :: 8;
    KEYPRESS   :: 9;
    UPDATE     :: 10;

    STEP       :: 11;
    SHORTCUT   :: 12;
    FREEMEM    :: 13;
    OTHER      :: 14;
    DRAWLABEL  :: 15;
    DBLCLICK   :: 16;
    TRPLCLICK  :: 17;
    ATTRIB     :: 18;
    KEYRELEASE :: 19;
    PS         :: 20;
    MOVEORIGIN :: 21;

    RESIZED    :: 22;

    PASTE      :: 23;
    TRIGGER    :: 24;

    MOVE       :: 6;
    KEYBOARD   :: 9;
    MOUSE      :: 10;

    FL_NOEVENT    :: NOEVENT;
    FL_DRAW       :: DRAW;
    FL_PUSH       :: PUSH;
    FL_RELEASE    :: RELEASE;
    FL_ENTER      :: ENTER;
    FL_LEAVE      :: LEAVE;
    FL_MOTION     :: MOTION;
    FL_FOCUS      :: FOCUS;
    FL_UNFOCUS    :: UNFOCUS;
    FL_KEYPRESS   :: KEYPRESS;
    FL_UPDATE     :: UPDATE;

    FL_STEP       :: STEP;
    FL_SHORTCUT   :: SHORTCUT;
    FL_FREEMEM    :: FREEMEM;
    FL_OTHER      :: OTHER;
    FL_DRAWLABEL  :: DRAWLABEL;
    FL_DBLCLICK   :: DBLCLICK;
    FL_TRPLCLICK  :: TRPLCLICK;
    FL_ATTRIB     :: ATTRIB;
    FL_KEYRELEASE :: KEYRELEASE;
    FL_PS         :: PS;
    FL_MOVEORIGIN :: MOVEORIGIN;

    FL_RESIZED    :: RESIZED;

    FL_PASTE      :: PASTE;
    FL_TRIGGER    :: TRIGGER;

    FL_MOVE       :: MOVE;
    FL_KEYBOARD   :: KEYBOARD;
    FL_MOUSE      :: MOUSE;
}

/* Resize policies */
FL_RESIZE_T :: enum u32 {
    NONE :: 0;
    X    :: 1;
    Y    :: 2;
    ALL  :: 3;

    FL_RESIZE_NONE :: NONE;
    FL_RESIZE_X    :: X;
    FL_RESIZE_Y    :: Y;
    FL_RESIZE_ALL  :: ALL;
}

/* Keyboard focus control */
FL_KEY :: enum u32 {
    NORMAL  :: 1;
    TAB     :: 2;
    SPECIAL :: 4;
    ALL     :: 7;

    FL_KEY_NORMAL  :: NORMAL;
    FL_KEY_TAB     :: TAB;
    FL_KEY_SPECIAL :: SPECIAL;
    FL_KEY_ALL     :: ALL;
}

/* Pop-up menu item attributes. NOTE if more than 8, need to change
* choice and menu class where mode is kept by a single byte */
FL_PUP :: enum u32 {
    NONE  :: 0;
    GREY  :: 1;
    BOX   :: 2;
    CHECK :: 4;
    RADIO :: 8;

    FL_PUP_NONE  :: NONE;
    FL_PUP_GREY  :: GREY;
    FL_PUP_BOX   :: BOX;
    FL_PUP_CHECK :: CHECK;
    FL_PUP_RADIO :: RADIO;
}

/* Popup and menu entries */
FL_PUP_CB :: #type (unknown0: s32) -> s32 #c_call;

FL_PUP_ENTRY :: struct {
    text:     *u8; /* label of a popup/menu item   */
    callback: FL_PUP_CB; /* the callback function        */
    shortcut: *u8; /* hotkeys                      */
    mode:     s32; /* FL_PUP_GRAY, FL_PUP_CHECK etc */
}

FL_TEXT_STYLE :: enum s32 {
    INVALID_STYLE         :: -1;
    NORMAL_STYLE          :: 0;
    BOLD_STYLE            :: 1;
    ITALIC_STYLE          :: 2;
    BOLDITALIC_STYLE      :: 3;

    FIXED_STYLE           :: 4;
    FIXEDBOLD_STYLE       :: 5;
    FIXEDITALIC_STYLE     :: 6;
    FIXEDBOLDITALIC_STYLE :: 7;

    TIMES_STYLE           :: 8;
    TIMESBOLD_STYLE       :: 9;
    TIMESITALIC_STYLE     :: 10;
    TIMESBOLDITALIC_STYLE :: 11;

    MISC_STYLE            :: 12;
    MISCBOLD_STYLE        :: 13;
    MISCITALIC_STYLE      :: 14;
    SYMBOL_STYLE          :: 15;

    SHADOW_STYLE          :: 512;
    ENGRAVED_STYLE        :: 1024;
    EMBOSSED_STYLE        :: 2048;

    FL_INVALID_STYLE         :: INVALID_STYLE;
    FL_NORMAL_STYLE          :: NORMAL_STYLE;
    FL_BOLD_STYLE            :: BOLD_STYLE;
    FL_ITALIC_STYLE          :: ITALIC_STYLE;
    FL_BOLDITALIC_STYLE      :: BOLDITALIC_STYLE;

    FL_FIXED_STYLE           :: FIXED_STYLE;
    FL_FIXEDBOLD_STYLE       :: FIXEDBOLD_STYLE;
    FL_FIXEDITALIC_STYLE     :: FIXEDITALIC_STYLE;
    FL_FIXEDBOLDITALIC_STYLE :: FIXEDBOLDITALIC_STYLE;

    FL_TIMES_STYLE           :: TIMES_STYLE;
    FL_TIMESBOLD_STYLE       :: TIMESBOLD_STYLE;
    FL_TIMESITALIC_STYLE     :: TIMESITALIC_STYLE;
    FL_TIMESBOLDITALIC_STYLE :: TIMESBOLDITALIC_STYLE;

    FL_MISC_STYLE            :: MISC_STYLE;
    FL_MISCBOLD_STYLE        :: MISCBOLD_STYLE;
    FL_MISCITALIC_STYLE      :: MISCITALIC_STYLE;
    FL_SYMBOL_STYLE          :: SYMBOL_STYLE;

    FL_SHADOW_STYLE          :: SHADOW_STYLE;
    FL_ENGRAVED_STYLE        :: ENGRAVED_STYLE;
    FL_EMBOSSED_STYLE        :: EMBOSSED_STYLE;
}

FL_FORM :: FL_FORM_;
FL_OBJECT :: FL_OBJECT_;
FL_pixmap :: FL_pixmap_;

FL_OBJECT_ :: struct {
    form:            *FL_FORM; /* the form this object belongs to */
    u_vdata:         *void; /* anything the user likes */
    u_cdata:         *u8; /* anything the user likes */
    u_ldata:         s64; /* anything the user likes */

    objclass:        s32; /* class of object, button, slider etc */
    type:            s32; /* type within the class */
    boxtype:         s32; /* what kind of box type */
    x:               FL_Coord; /* current obj. location and size */
    y:               FL_Coord;
    w:               FL_Coord;
    h:               FL_Coord;
    fl1:             float64; /* distances of upper left hand (1) and */
    fr1:             float64; /* lower right hand corner (2) to left, */
    ft1:             float64; /* right, top and bottom of enclosing   */
    fb1:             float64; /* form */
    fl2:             float64;
    fr2:             float64;
    ft2:             float64;
    fb2:             float64;
    bw:              FL_Coord;
    col1:            FL_COLOR; /* colors of obj */
    col2:            FL_COLOR;
    label:           *u8; /* object label */
    lcol:            FL_COLOR; /* label color */
    align:           s32;
    lsize:           s32; /* label size and style */
    lstyle:          s32;
    shortcut:        *s64;
    handle:          #type (unknown0: *FL_OBJECT, unknown1: s32, unknown2: FL_Coord, unknown3: FL_Coord, unknown4: s32, unknown5: *void) -> s32 #c_call;

    object_callback: #type (unknown0: *FL_OBJECT, unknown1: s64) -> void #c_call;

    argument:        s64;
    spec:            *void; /* instantiation */

    prehandle:       #type (unknown0: *FL_OBJECT, unknown1: s32, unknown2: FL_Coord, unknown3: FL_Coord, unknown4: s32, unknown5: *void) -> s32 #c_call;

    posthandle:      #type (unknown0: *FL_OBJECT, unknown1: s32, unknown2: FL_Coord, unknown3: FL_Coord, unknown4: s32, unknown5: *void) -> s32 #c_call;

    set_return:      #type (unknown0: *FL_OBJECT, unknown1: u32) -> void #c_call;

    resize:          u32; /* what to do if WM resizes the FORM     */
    nwgravity:       u32; /* how to re-position top-left corner    */
    segravity:       u32; /* how to re-position lower-right corner */

    prev:            *FL_OBJECT; /* prev. obj in form */
    next:            *FL_OBJECT; /* next. obj in form */

    parent:          *FL_OBJECT;
    child:           *FL_OBJECT;
    nc:              *FL_OBJECT; /* next child */

    flpixmap:        *FL_pixmap; /* pixmap double buffering stateinfo */
    use_pixmap:      s32; /* true to use pixmap double buffering*/

    returned:        s32; /* what last interaction returned */
    how_return:      u32; /* under which conditions to return */
    double_buffer:   s32; /* only used by mesa/gl canvas */
    pushed:          s32;
    focus:           s32;
    belowmouse:      s32;
    active:          s32; /* if object accepts events */
    input:           s32;
    wantkey:         s32;
    radio:           s32;
    automatic:       s32;
    redraw:          s32;
    visible:         s32;
    is_under:        s32; /* if (partially) hidden by other object */
    clip:            s32;
    click_timeout:   u64;
    c_vdata:         *void; /* for class use */
    c_cdata:         *u8; /* for class use */
    c_ldata:         s64; /* for class use */
    dbl_background:  FL_COLOR; /* double buffer background */
    tooltip:         *u8;
    tipID:           s32;
    group_id:        s32;
    want_motion:     s32;
    want_update:     s32;
}

/* Callback function for an entire form */
FL_FORMCALLBACKPTR :: #type (unknown0: *FL_OBJECT, unknown1: *void) -> void #c_call;

/* Object callback function      */
FL_CALLBACKPTR :: #type (unknown0: *FL_OBJECT, unknown1: s64) -> void #c_call;

/* Preemptive callback function  */
FL_RAW_CALLBACK :: #type (unknown0: *FL_FORM, unknown1: *void) -> s32 #c_call;

/* At close (WM menu delete/close etc.) function */
FL_FORM_ATCLOSE :: #type (unknown0: *FL_FORM, unknown1: *void) -> s32 #c_call;

/* Deactivate/activate callback */
FL_FORM_ATDEACTIVATE :: #type (unknown0: *FL_FORM, unknown1: *void) -> void #c_call;

FL_FORM_ATACTIVATE :: #type (unknown0: *FL_FORM, unknown1: *void) -> void #c_call;

FL_HANDLEPTR :: #type (unknown0: *FL_OBJECT, unknown1: s32, unknown2: FL_Coord, unknown3: FL_Coord, unknown4: s32, unknown5: *void) -> s32 #c_call;

/* Error callback */
FL_ERROR_FUNC :: #type (unknown0: *u8, unknown1: *u8, __args: ..Any) -> void #c_call;

FL_EVENT: *FL_OBJECT #elsewhere libforms;

/* Form visibility state: form->visible */
FL_3 :: enum s32 {
    BEING_HIDDEN :: -1;
    HIDDEN       :: 0;
    INVISIBLE    :: 0;
    VISIBLE      :: 1;

    FL_BEING_HIDDEN :: BEING_HIDDEN;
    FL_HIDDEN       :: HIDDEN;
    FL_INVISIBLE    :: INVISIBLE;
    FL_VISIBLE      :: VISIBLE;
}

FL_FORM_ :: struct {
    fdui:                *void; /* for fdesign */
    u_vdata:             *void; /* for application */
    u_cdata:             *u8; /* for application */
    u_ldata:             s64; /* for application */

    label:               *u8; /* window title */
    window:              Window; /* X resource ID for window */
    x:                   FL_Coord; /* current geometry info */
    y:                   FL_Coord;
    w:                   FL_Coord;
    h:                   FL_Coord;
    handle_dec_x:        s32;
    handle_dec_y:        s32;
    hotx:                FL_Coord; /* hot-spot of the form */
    hoty:                FL_Coord;
    w_hr:                float64; /* high resolution width and height */
    h_hr:                float64; /* (needed for precise scaling) */

    first:               *FL_OBJECT;
    last:                *FL_OBJECT;
    focusobj:            *FL_OBJECT;

    form_callback:       FL_FORMCALLBACKPTR;
    activate_callback:   FL_FORM_ATACTIVATE;
    deactivate_callback: FL_FORM_ATDEACTIVATE;
    form_cb_data:        *void;
    activate_data:       *void;
    deactivate_data:     *void;

    key_callback:        FL_RAW_CALLBACK;
    push_callback:       FL_RAW_CALLBACK;
    crossing_callback:   FL_RAW_CALLBACK;
    motion_callback:     FL_RAW_CALLBACK;
    all_callback:        FL_RAW_CALLBACK;

    compress_mask:       u64;
    evmask:              u64;

    /* WM_DELETE_WINDOW message handler */
    close_callback:      FL_FORM_ATCLOSE;
    close_data:          *void;

    flpixmap:            *FL_pixmap; /* back buffer */

    icon_pixmap:         Pixmap;
    icon_mask:           Pixmap;

    deactivated:         s32; /* non-zero if deactivated */
    use_pixmap:          s32; /* true if dbl buffering */
    frozen:              s32; /* true if sync change */
    visible:             s32; /* true if mapped */
    wm_border:           s32; /* window manager info */
    prop:                u32; /* other attributes */
    num_auto_objects:    s32;
    needs_full_redraw:   s32;
    sort_of_modal:       s32; /* internal use */
    parent:              *FL_FORM;
    child:               *FL_FORM;
    parent_obj:          *FL_OBJECT;
    attached:            s32; /* not independent anymore */
    pre_attach:          #type (unknown0: *FL_FORM) -> void #c_call;
    attach_data:         *void;
    in_redraw:           s32;
}

/* All FD_xxx structure emitted by fdesign contains at least the
* following */
FD_Any :: struct {
    form:  *FL_FORM;
    vdata: *void;
    cdata: *u8;
    ldata: s64;
}

/* Async IO stuff */
FL_4 :: enum u32 {
    READ   :: 1;
    WRITE  :: 2;
    EXCEPT :: 4;

    FL_READ   :: READ;
    FL_WRITE  :: WRITE;
    FL_EXCEPT :: EXCEPT;
}

/* IO other than XEvent Q */
FL_IO_CALLBACK :: #type (unknown0: s32, unknown1: *void) -> void #c_call;

fl_add_io_callback :: (fd: s32, mask: u32, callback: FL_IO_CALLBACK, data: *void) -> void #foreign libforms;

fl_remove_io_callback :: (fd: s32, mask: u32, cb: FL_IO_CALLBACK) -> void #foreign libforms;

/* signals */
FL_SIGNAL_HANDLER :: #type (unknown0: s32, unknown1: *void) -> void #c_call;

fl_add_signal_callback :: (s: s32, cb: FL_SIGNAL_HANDLER, data: *void) -> void #foreign libforms;

fl_remove_signal_callback :: (s: s32) -> void #foreign libforms;

fl_signal_caught :: (s: s32) -> void #foreign libforms;

fl_app_signal_direct :: (y: s32) -> void #foreign libforms;

FL_INPUT_END_EVENT :: enum u32 {
    CLASSIC :: 0;
    ALWAYS  :: 1;

    FL_INPUT_END_EVENT_CLASSIC :: CLASSIC;
    FL_INPUT_END_EVENT_ALWAYS  :: ALWAYS;
}

fl_input_end_return_handling :: (type: s32) -> s32 #foreign libforms;

/* Timeouts */
FL_TIMEOUT_CALLBACK :: #type (unknown0: s32, unknown1: *void) -> void #c_call;

fl_add_timeout :: (msec: s64, callback: FL_TIMEOUT_CALLBACK, data: *void) -> s32 #foreign libforms;

fl_remove_timeout :: (id: s32) -> void #foreign libforms;

/* Basic public routine prototypes */
fl_library_version :: (ver: *s32, rev: *s32) -> s32 #foreign libforms;

fl_library_full_version :: (version: *s32, revision: *s32, fix_level: *s32, extra: **u8) -> s64 #foreign libforms;

/** Generic routines that deal with FORMS **/
fl_bgn_form :: (type: s32, w: FL_Coord, h: FL_Coord) -> *FL_FORM #foreign libforms;

fl_end_form :: () -> void #foreign libforms;

fl_do_forms :: () -> *FL_OBJECT #foreign libforms;

fl_check_forms :: () -> *FL_OBJECT #foreign libforms;

fl_do_only_forms :: () -> *FL_OBJECT #foreign libforms;

fl_check_only_forms :: () -> *FL_OBJECT #foreign libforms;

fl_freeze_form :: (form: *FL_FORM) -> void #foreign libforms;

fl_set_focus_object :: (form: *FL_FORM, obj: *FL_OBJECT) -> void #foreign libforms;

fl_get_focus_object :: (form: *FL_FORM) -> *FL_OBJECT #foreign libforms;

fl_reset_focus_object :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_set_form_atclose :: (form: *FL_FORM, fmclose: FL_FORM_ATCLOSE, data: *void) -> FL_FORM_ATCLOSE #foreign libforms;

fl_set_atclose :: (fmclose: FL_FORM_ATCLOSE, data: *void) -> FL_FORM_ATCLOSE #foreign libforms;

fl_set_form_atactivate :: (form: *FL_FORM, cb: FL_FORM_ATACTIVATE, data: *void) -> FL_FORM_ATACTIVATE #foreign libforms;

fl_set_form_atdeactivate :: (form: *FL_FORM, cb: FL_FORM_ATDEACTIVATE, data: *void) -> FL_FORM_ATDEACTIVATE #foreign libforms;

fl_unfreeze_form :: (form: *FL_FORM) -> void #foreign libforms;

fl_form_is_activated :: (form: *FL_FORM) -> s32 #foreign libforms;

fl_deactivate_form :: (form: *FL_FORM) -> void #foreign libforms;

fl_activate_form :: (form: *FL_FORM) -> void #foreign libforms;

fl_deactivate_all_forms :: () -> void #foreign libforms;

fl_activate_all_forms :: () -> void #foreign libforms;

fl_freeze_all_forms :: () -> void #foreign libforms;

fl_unfreeze_all_forms :: () -> void #foreign libforms;

fl_scale_form :: (form: *FL_FORM, xsc: float64, ysc: float64) -> void #foreign libforms;

fl_set_form_position :: (form: *FL_FORM, x: FL_Coord, y: FL_Coord) -> void #foreign libforms;

fl_set_form_title :: (form: *FL_FORM, name: *u8) -> void #foreign libforms;

fl_set_form_title_f_CFormat :: (form: *FL_FORM, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_set_form_title_f";
fl_set_form_title_f :: (form: *FL_FORM, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_set_form_title_f_CFormat(form, "%s", formatted_text.data);
} @PrintLike

fl_set_app_mainform :: (form: *FL_FORM) -> void #foreign libforms;

fl_get_app_mainform :: () -> *FL_FORM #foreign libforms;

fl_set_app_nomainform :: (flag: s32) -> void #foreign libforms;

fl_set_form_callback :: (form: *FL_FORM, callback: FL_FORMCALLBACKPTR, d: *void) -> void #foreign libforms;

fl_set_form_size :: (form: *FL_FORM, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_set_form_background_color :: (form: *FL_FORM, color: FL_COLOR) -> void #foreign libforms;

fl_get_form_background_color :: (form: *FL_FORM) -> FL_COLOR #foreign libforms;

fl_set_form_hotspot :: (form: *FL_FORM, x: FL_Coord, y: FL_Coord) -> void #foreign libforms;

fl_set_form_hotobject :: (form: *FL_FORM, ob: *FL_OBJECT) -> void #foreign libforms;

fl_set_form_minsize :: (form: *FL_FORM, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_set_form_maxsize :: (form: *FL_FORM, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_set_form_event_cmask :: (form: *FL_FORM, cmask: u64) -> void #foreign libforms;

fl_get_form_event_cmask :: (form: *FL_FORM) -> u64 #foreign libforms;

fl_set_form_geometry :: (form: *FL_FORM, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_show_form :: (form: *FL_FORM, place: s32, border: s32, name: *u8) -> Window #foreign libforms;

fl_show_form_f_CFormat :: (form: *FL_FORM, place: s32, border: s32, fmt: *u8, __args: ..Any) -> Window #foreign libforms "fl_show_form_f";
fl_show_form_f :: (form: *FL_FORM, place: s32, border: s32, fmt: string, __args: ..Any) -> Window {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_show_form_f_CFormat(form, place, border, "%s", formatted_text.data);
} @PrintLike

fl_hide_form :: (form: *FL_FORM) -> void #foreign libforms;

fl_free_form :: (form: *FL_FORM) -> void #foreign libforms;

fl_redraw_form :: (form: *FL_FORM) -> void #foreign libforms;

fl_set_form_dblbuffer :: (form: *FL_FORM, y: s32) -> void #foreign libforms;

fl_prepare_form_window :: (form: *FL_FORM, place: s32, border: s32, name: *u8) -> Window #foreign libforms;

fl_prepare_form_window_f_CFormat :: (form: *FL_FORM, place: s32, border: s32, fmt: *u8, __args: ..Any) -> Window #foreign libforms "fl_prepare_form_window_f";
fl_prepare_form_window_f :: (form: *FL_FORM, place: s32, border: s32, fmt: string, __args: ..Any) -> Window {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_prepare_form_window_f_CFormat(form, place, border, "%s", formatted_text.data);
} @PrintLike

fl_show_form_window :: (form: *FL_FORM) -> Window #foreign libforms;

fl_adjust_form_size :: (form: *FL_FORM) -> float64 #foreign libforms;

fl_form_is_visible :: (form: *FL_FORM) -> s32 #foreign libforms;

fl_form_is_iconified :: (form: *FL_FORM) -> s32 #foreign libforms;

fl_register_raw_callback :: (form: *FL_FORM, mask: u64, rcb: FL_RAW_CALLBACK) -> FL_RAW_CALLBACK #foreign libforms;

fl_bgn_group :: () -> *FL_OBJECT #foreign libforms;

fl_end_group :: () -> void #foreign libforms;

fl_addto_group :: (group: *FL_OBJECT) -> *FL_OBJECT #foreign libforms;

/****** Routines that deal with FL_OBJECTS ********/
fl_get_object_objclass :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_object_type :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_object_boxtype :: (ob: *FL_OBJECT, boxtype: s32) -> void #foreign libforms;

fl_get_object_boxtype :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_object_bw :: (ob: *FL_OBJECT, bw: s32) -> void #foreign libforms;

fl_get_object_bw :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_object_resize :: (ob: *FL_OBJECT, what: u32) -> void #foreign libforms;

fl_get_object_resize :: (ob: *FL_OBJECT, what: *u32) -> void #foreign libforms;

fl_set_object_gravity :: (ob: *FL_OBJECT, nw: u32, se: u32) -> void #foreign libforms;

fl_get_object_gravity :: (ob: *FL_OBJECT, nw: *u32, se: *u32) -> void #foreign libforms;

fl_set_object_lsize :: (obj: *FL_OBJECT, lsize: s32) -> void #foreign libforms;

fl_get_object_lsize :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_object_lstyle :: (obj: *FL_OBJECT, lstyle: s32) -> void #foreign libforms;

fl_get_object_lstyle :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_object_lcol :: (ob: *FL_OBJECT, lcol: FL_COLOR) -> void #foreign libforms;

fl_get_object_lcol :: (obj: *FL_OBJECT) -> FL_COLOR #foreign libforms;

fl_set_object_return :: (ob: *FL_OBJECT, when: u32) -> u32 #foreign libforms;

fl_get_object_return :: (ob: *FL_OBJECT) -> u32 #foreign libforms;

fl_set_object_lalign :: (obj: *FL_OBJECT, align: s32) -> void #foreign libforms;

fl_get_object_lalign :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_object_shortcut :: (obj: *FL_OBJECT, sstr: *u8, showit: s32) -> void #foreign libforms;

fl_set_object_shortcutkey :: (obj: *FL_OBJECT, keysym: u32) -> void #foreign libforms;

fl_set_object_dblbuffer :: (ob: *FL_OBJECT, y: s32) -> void #foreign libforms;

fl_set_object_color :: (ob: *FL_OBJECT, col1: FL_COLOR, col2: FL_COLOR) -> void #foreign libforms;

fl_get_object_color :: (obj: *FL_OBJECT, col1: *FL_COLOR, col2: *FL_COLOR) -> void #foreign libforms;

fl_set_object_label :: (ob: *FL_OBJECT, label: *u8) -> void #foreign libforms;

fl_set_object_label_f_CFormat :: (obj: *FL_OBJECT, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_set_object_label_f";
fl_set_object_label_f :: (obj: *FL_OBJECT, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_set_object_label_f_CFormat(obj, "%s", formatted_text.data);
} @PrintLike

fl_get_object_label :: (obj: *FL_OBJECT) -> *u8 #foreign libforms;

fl_set_object_helper :: (ob: *FL_OBJECT, tip: *u8) -> void #foreign libforms;

fl_set_object_helper_f_CFormat :: (ob: *FL_OBJECT, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_set_object_helper_f";
fl_set_object_helper_f :: (ob: *FL_OBJECT, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_set_object_helper_f_CFormat(ob, "%s", formatted_text.data);
} @PrintLike

fl_set_object_position :: (obj: *FL_OBJECT, x: FL_Coord, y: FL_Coord) -> void #foreign libforms;

fl_get_object_size :: (obj: *FL_OBJECT, w: *FL_Coord, h: *FL_Coord) -> void #foreign libforms;

fl_set_object_size :: (obj: *FL_OBJECT, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_set_object_automatic :: (obj: *FL_OBJECT, flag: s32) -> void #foreign libforms;

fl_object_is_automatic :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_draw_object_label :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_draw_object_label_outside :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_get_object_component :: (composite: *FL_OBJECT, objclass: s32, type: s32, numb: s32) -> *FL_OBJECT #foreign libforms;

fl_for_all_objects :: (form: *FL_FORM, cb: #type (unknown0: *FL_OBJECT, unknown1: *void) -> s32 #c_call, v: *void) -> void #foreign libforms;

fl_set_object_dblclick :: (obj: *FL_OBJECT, timeout: u64) -> void #foreign libforms;

fl_get_object_dblclick :: (obj: *FL_OBJECT) -> u64 #foreign libforms;

fl_set_object_geometry :: (obj: *FL_OBJECT, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_move_object :: (obj: *FL_OBJECT, dx: FL_Coord, dy: FL_Coord) -> void #foreign libforms;

fl_fit_object_label :: (obj: *FL_OBJECT, xmargin: FL_Coord, ymargin: FL_Coord) -> void #foreign libforms;

fl_get_object_geometry :: (ob: *FL_OBJECT, x: *FL_Coord, y: *FL_Coord, w: *FL_Coord, h: *FL_Coord) -> void #foreign libforms;

fl_get_object_position :: (ob: *FL_OBJECT, x: *FL_Coord, y: *FL_Coord) -> void #foreign libforms;

/* This one takes into account the label */
fl_get_object_bbox :: (obj: *FL_OBJECT, x: *FL_Coord, y: *FL_Coord, w: *FL_Coord, h: *FL_Coord) -> void #foreign libforms;

fl_call_object_callback :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_set_object_prehandler :: (ob: *FL_OBJECT, phandler: FL_HANDLEPTR) -> FL_HANDLEPTR #foreign libforms;

fl_set_object_posthandler :: (ob: *FL_OBJECT, post: FL_HANDLEPTR) -> FL_HANDLEPTR #foreign libforms;

fl_set_object_callback :: (obj: *FL_OBJECT, callback: FL_CALLBACKPTR, argument: s64) -> FL_CALLBACKPTR #foreign libforms;

fl_redraw_object :: (obj: *FL_OBJECT) -> void #foreign libforms;

fl_show_object :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_hide_object :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_object_is_visible :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_free_object :: (obj: *FL_OBJECT) -> void #foreign libforms;

fl_delete_object :: (obj: *FL_OBJECT) -> void #foreign libforms;

fl_get_object_return_state :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_trigger_object :: (obj: *FL_OBJECT) -> void #foreign libforms;

fl_activate_object :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_deactivate_object :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_object_is_active :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_enumerate_fonts :: (output: #type (s: *u8) -> void #c_call, shortform: s32) -> s32 #foreign libforms;

fl_set_font_name :: (n: s32, name: *u8) -> s32 #foreign libforms;

fl_set_font_name_f_CFormat :: (n: s32, fmt: *u8, __args: ..Any) -> s32 #foreign libforms "fl_set_font_name_f";
fl_set_font_name_f :: (n: s32, fmt: string, __args: ..Any) -> s32 {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_set_font_name_f_CFormat(n, "%s", formatted_text.data);
} @PrintLike

fl_get_font_name :: (n: s32) -> *u8 #foreign libforms;

fl_set_font :: (numb: s32, size: s32) -> void #foreign libforms;

/* Routines that facilitate free object */
fl_get_char_height :: (style: s32, size: s32, asc: *s32, desc: *s32) -> s32 #foreign libforms;

fl_get_char_width :: (style: s32, size: s32) -> s32 #foreign libforms;

fl_get_string_height :: (style: s32, size: s32, s: *u8, len: s32, asc: *s32, desc: *s32) -> s32 #foreign libforms;

fl_get_string_width :: (style: s32, size: s32, s: *u8, len: s32) -> s32 #foreign libforms;

fl_get_string_widthTAB :: (style: s32, size: s32, s: *u8, len: s32) -> s32 #foreign libforms;

fl_get_string_dimension :: (fntstyle: s32, fntsize: s32, s: *u8, len: s32, width: *s32, height: *s32) -> void #foreign libforms;

fl_get_align_xy :: (align: s32, x: s32, y: s32, w: s32, h: s32, xsize: s32, ysize: s32, xoff: s32, yoff: s32, _xx: *s32, yy: *s32) -> void #foreign libforms;

fl_get_label_char_at_mouse :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_draw_text :: (align: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, c: FL_COLOR, style: s32, size: s32, istr: *u8) -> void #foreign libforms;

fl_draw_text_beside :: (align: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, c: FL_COLOR, style: s32, size: s32, str: *u8) -> void #foreign libforms;

fl_draw_text_cursor :: (align: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, c: FL_COLOR, style: s32, size: s32, str: *u8, cc: FL_COLOR, pos: s32) -> void #foreign libforms;

fl_draw_box :: (style: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, c: FL_COLOR, bw_in: s32) -> void #foreign libforms;

FL_DRAWPTR :: #type (unknown0: FL_Coord, unknown1: FL_Coord, unknown2: FL_Coord, unknown3: FL_Coord, unknown4: s32, unknown5: FL_COLOR) -> void #c_call;

fl_add_symbol :: (name: *u8, drawit: FL_DRAWPTR, scalable: s32) -> s32 #foreign libforms;

fl_delete_symbol :: (name: *u8) -> s32 #foreign libforms;

fl_draw_symbol :: (label: *u8, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, col: FL_COLOR) -> s32 #foreign libforms;

fl_mapcolor :: (col: FL_COLOR, r: s32, g: s32, b: s32) -> u64 #foreign libforms;

fl_mapcolorname :: (col: FL_COLOR, name: *u8) -> s64 #foreign libforms;

fl_free_colors :: (c: *FL_COLOR, n: s32) -> void #foreign libforms;

fl_free_pixels :: (pix: *u64, n: s32) -> void #foreign libforms;

fl_set_color_leak :: (y: s32) -> void #foreign libforms;

fl_getmcolor :: (i: FL_COLOR, r: *s32, g: *s32, b: *s32) -> u64 #foreign libforms;

fl_get_pixel :: (col: FL_COLOR) -> u64 #foreign libforms;

fl_get_icm_color :: (col: FL_COLOR, r: *s32, g: *s32, b: *s32) -> void #foreign libforms;

fl_set_icm_color :: (col: FL_COLOR, r: s32, g: s32, b: s32) -> void #foreign libforms;

fl_color :: (col: FL_COLOR) -> void #foreign libforms;

fl_bk_color :: (col: FL_COLOR) -> void #foreign libforms;

fl_set_gamma :: (r: float64, g: float64, b: float64) -> void #foreign libforms;

fl_show_errors :: (y: s32) -> void #foreign libforms;

FL_FSCB :: #type (unknown0: *u8, unknown1: *void) -> s32 #c_call;

/* Utilities for new objects */
fl_current_form: *FL_FORM #elsewhere libforms;

fl_add_object :: (form: *FL_FORM, obj: *FL_OBJECT) -> void #foreign libforms;

fl_addto_form :: (form: *FL_FORM) -> *FL_FORM #foreign libforms;

fl_make_object :: (objclass: s32, type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8, handle: FL_HANDLEPTR) -> *FL_OBJECT #foreign libforms;

fl_add_child :: (unknown0: *FL_OBJECT, unknown1: *FL_OBJECT) -> void #foreign libforms;

fl_set_coordunit :: (u: s32) -> void #foreign libforms;

fl_set_border_width :: (bw: s32) -> void #foreign libforms;

fl_set_scrollbar_type :: (t: s32) -> void #foreign libforms;

fl_flip_yorigin :: () -> void #foreign libforms;

fl_get_coordunit :: () -> s32 #foreign libforms;

fl_get_border_width :: () -> s32 #foreign libforms;

/* Misc. routines */
fl_ringbell :: (percent: s32) -> void #foreign libforms;

fl_gettime :: (sec: *s64, usec: *s64) -> void #foreign libforms;

fl_now :: () -> *u8 #foreign libforms;

fl_whoami :: () -> *u8 #foreign libforms;

fl_mouse_button :: () -> s64 #foreign libforms;

fl_current_event :: () -> s32 #foreign libforms;

fl_strdup :: (s: *u8) -> *u8 #foreign libforms;

fl_set_err_logfp :: (fp: *FILE) -> void #foreign libforms;

fl_set_error_handler :: (user_func: FL_ERROR_FUNC) -> void #foreign libforms;

fl_get_cmdline_args :: (unknown0: *s32) -> **u8 #foreign libforms;

/* These give more flexibility for future changes. Also application
* can re-assign these pointers to whatever function it wants, e.g.,
* to a shared memory pool allocator. */
fl_free: #type (unknown0: *void) -> void #c_call #elsewhere libforms;

fl_malloc: #type (unknown0: u64) -> *void #c_call #elsewhere libforms;

fl_calloc: #type (unknown0: u64, unknown1: u64) -> *void #c_call #elsewhere libforms;

fl_realloc: #type (unknown0: *void, unknown1: u64) -> *void #c_call #elsewhere libforms;

fl_msleep :: (msec: u64) -> s32 #foreign libforms;

FL_VAL_FILTER :: #type (unknown0: *FL_OBJECT, unknown1: float64, unknown2: s32) -> *u8 #c_call;

fl_is_same_object :: (obj1: *FL_OBJECT, obj2: *FL_OBJECT) -> s32 #foreign libforms;

/* Draw mode */
FL_5 :: enum u32 {
    XOR  :: 6;
    COPY :: 3;
    AND  :: 1;

    FL_XOR  :: XOR;
    FL_COPY :: COPY;
    FL_AND  :: AND;
}

/* FL_xxx does not do anything anymore, but kept for compatibility */
FL_6 :: enum s32 {
    IllegalVisual :: -1;
    StaticGray    :: 0;
    GrayScale     :: 1;
    StaticColor   :: 2;
    PseudoColor   :: 3;
    TrueColor     :: 4;
    DirectColor   :: 5;
    DefaultVisual :: 10;

    FL_IllegalVisual :: IllegalVisual;
    FL_StaticGray    :: StaticGray;
    FL_GrayScale     :: GrayScale;
    FL_StaticColor   :: StaticColor;
    FL_PseudoColor   :: PseudoColor;
    FL_TrueColor     :: TrueColor;
    FL_DirectColor   :: DirectColor;
    FL_DefaultVisual :: DefaultVisual;
}

FL_7 :: enum u32 {
    North         :: 2;
    NorthEast     :: 3;
    NorthWest     :: 1;
    South         :: 8;
    SouthEast     :: 9;
    SouthWest     :: 7;
    East          :: 6;
    West          :: 4;
    NoGravity     :: 0;
    ForgetGravity :: 0;

    FL_North         :: North;
    FL_NorthEast     :: NorthEast;
    FL_NorthWest     :: NorthWest;
    FL_South         :: South;
    FL_SouthEast     :: SouthEast;
    FL_SouthWest     :: SouthWest;
    FL_East          :: East;
    FL_West          :: West;
    FL_NoGravity     :: NoGravity;
    FL_ForgetGravity :: ForgetGravity;
}

/* FL graphics state information. Some are redundant. */
FL_State :: struct {
    xvinfo:      *XVisualInfo;
    cur_fnt:     *XFontStruct; /* current font in default GC */
    colormap:    Colormap; /* colormap valid for xvinfo */
    trailblazer: Window; /* a valid window for xvinfo */
    vclass:      s32; /* visual class and color depth */
    depth:       s32;
    rgb_bits:    s32; /* primary color resolution */
    dithered:    s32; /* true if dithered color */
    pcm:         s32; /* true if colormap is not shared */
    gc:          [16] GC; /* working GC */
    textgc:      [16] GC; /* GC used exclusively for text */
    dimmedGC:    GC; /* A GC having a checkboard stipple */
    lut:         [1024] u64; /* secondary lookup table */
    rshift:      u32;
    rmask:       u32;
    rbits:       u32;
    gshift:      u32;
    gmask:       u32;
    gbits:       u32;
    bshift:      u32;
    bmask:       u32;
    bbits:       u32;
}

/***** Global variables ******/
fl_display: *Display #elsewhere libforms;

fl_screen: s32 #elsewhere libforms;

fl_root: Window #elsewhere libforms; /* root window */
fl_vroot: Window #elsewhere libforms; /* virtual root window */
fl_scrh: s32 #elsewhere libforms; /* screen dimension in pixels */
fl_scrw: s32 #elsewhere libforms;
fl_vmode: s32 #elsewhere libforms;

fl_state: *FL_State #elsewhere libforms;

fl_ul_magic_char: *u8 #elsewhere libforms;

fl_dpi: float64 #elsewhere libforms;

fl_mode_capable :: (mode: s32, warn: s32) -> s32 #foreign libforms;

/* All pixmaps used by FL_OBJECT to simulate double buffering have the
* following entries in the structure. FL_Coord x,y are used to shift
* the origin of the drawing routines */
FL_pixmap_ :: struct {
    pixmap:         Pixmap;
    win:            Window;
    visual:         *Visual;
    x:              FL_Coord;
    y:              FL_Coord;
    w:              FL_Coord;
    h:              FL_Coord;
    depth:          s32;
    dbl_background: FL_COLOR;
    pixel:          FL_COLOR;
}

FL_FONT :: struct {
    fs:    [10] *XFontStruct; /* cached fontstruct */
    size:  [10] s16; /* cached sizes */
    nsize: s16; /* cached so far */
    fname: [81] u8; /* without size info */
}

/* Some basic drawing routines */
FL_POINT :: XPoint;
FL_RECT :: XRectangle;

/* Rectangles */
fl_rectangle :: (fill: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, col: FL_COLOR) -> void #foreign libforms;

fl_rectbound :: (x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, col: FL_COLOR) -> void #foreign libforms;

/* Rectangle with rounded-corners */
fl_roundrectangle :: (fill: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, col: FL_COLOR) -> void #foreign libforms;

/* General polygon and polylines */
fl_polygon :: (fill: s32, xp: *FL_POINT, n: s32, col: FL_COLOR) -> void #foreign libforms;

fl_lines :: (xp: *FL_POINT, n: s32, col: FL_COLOR) -> void #foreign libforms;

fl_line :: (xi: FL_Coord, yi: FL_Coord, xf: FL_Coord, yf: FL_Coord, c: FL_COLOR) -> void #foreign libforms;

fl_point :: (x: FL_Coord, y: FL_Coord, c: FL_COLOR) -> void #foreign libforms;

fl_points :: (p: *FL_POINT, np: s32, c: FL_COLOR) -> void #foreign libforms;

fl_dashedlinestyle :: (dash: *u8, ndash: s32) -> void #foreign libforms;

fl_update_display :: (block: s32) -> void #foreign libforms;

/* Line attributes */
FL_8 :: enum u32 {
    SOLID          :: 0;
    USERDASH       :: 1;
    USERDOUBLEDASH :: 2;
    DOT            :: 3;
    DOTDASH        :: 4;
    DASH           :: 5;
    LONGDASH       :: 6;

    FL_SOLID          :: SOLID;
    FL_USERDASH       :: USERDASH;
    FL_USERDOUBLEDASH :: USERDOUBLEDASH;
    FL_DOT            :: DOT;
    FL_DOTDASH        :: DOTDASH;
    FL_DASH           :: DASH;
    FL_LONGDASH       :: LONGDASH;
}

fl_linewidth :: (n: s32) -> void #foreign libforms;

fl_linestyle :: (n: s32) -> void #foreign libforms;

fl_drawmode :: (request: s32) -> void #foreign libforms;

fl_get_linewidth :: () -> s32 #foreign libforms;

fl_get_linestyle :: () -> s32 #foreign libforms;

fl_get_drawmode :: () -> s32 #foreign libforms;

/** Ellipses **/
fl_circ :: (x: FL_Coord, y: FL_Coord, r: FL_Coord, col: FL_COLOR) -> void #foreign libforms;

fl_circf :: (x: FL_Coord, y: FL_Coord, r: FL_Coord, col: FL_COLOR) -> void #foreign libforms;

fl_circbound :: (x: FL_Coord, y: FL_Coord, r: FL_Coord, col: FL_COLOR) -> void #foreign libforms;

fl_oval :: (fill: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, col: FL_COLOR) -> void #foreign libforms;

fl_ovalbound :: (x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, col: FL_COLOR) -> void #foreign libforms;

fl_ovalarc :: (fill: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, t0: s32, dt: s32, col: FL_COLOR) -> void #foreign libforms;

/* Arcs */
fl_arcf :: (x: FL_Coord, y: FL_Coord, r: FL_Coord, a1: s32, a2: s32, col: FL_COLOR) -> void #foreign libforms;

fl_arc :: (x: FL_Coord, y: FL_Coord, r: FL_Coord, a1: s32, a2: s32, col: FL_COLOR) -> void #foreign libforms;

fl_pieslice :: (fill: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, a1: s32, a2: s32, col: FL_COLOR) -> void #foreign libforms;

fl_draw_frame :: (style: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, c: FL_COLOR, bw: s32) -> void #foreign libforms;

/*
* Interfaces
*/
fl_get_fontstruct :: (style: s32, size: s32) -> *XFontStruct #foreign libforms;

fl_get_mouse :: (x: *FL_Coord, y: *FL_Coord, keymask: *u32) -> Window #foreign libforms;

fl_set_mouse :: (mx: FL_Coord, my: FL_Coord) -> void #foreign libforms;

fl_get_win_mouse :: (win: Window, x: *FL_Coord, y: *FL_Coord, keymask: *u32) -> Window #foreign libforms;

fl_get_form_mouse :: (fm: *FL_FORM, x: *FL_Coord, y: *FL_Coord, keymask: *u32) -> Window #foreign libforms;

fl_win_to_form :: (win: Window) -> *FL_FORM #foreign libforms;

fl_set_form_icon :: (form: *FL_FORM, p: Pixmap, m: Pixmap) -> void #foreign libforms;

fl_get_decoration_sizes :: (form: *FL_FORM, top: *s32, right: *s32, bottom: *s32, left: *s32) -> s32 #foreign libforms;

fl_raise_form :: (form: *FL_FORM) -> void #foreign libforms;

fl_lower_form :: (form: *FL_FORM) -> void #foreign libforms;

fl_set_foreground :: (gc: GC, color: FL_COLOR) -> void #foreign libforms;

fl_set_background :: (gc: GC, color: FL_COLOR) -> void #foreign libforms;

/* General windowing support */
fl_wincreate :: (label: *u8) -> Window #foreign libforms;

fl_winshow :: (win: Window) -> Window #foreign libforms;

fl_winopen :: (label: *u8) -> Window #foreign libforms;

fl_winhide :: (win: Window) -> void #foreign libforms;

fl_winclose :: (win: Window) -> void #foreign libforms;

fl_winset :: (win: Window) -> void #foreign libforms;

fl_winreparent :: (win: Window, new_parent: Window) -> s32 #foreign libforms;

fl_winfocus :: (win: Window) -> void #foreign libforms;

fl_winget :: () -> Window #foreign libforms;

fl_iconify :: (win: Window) -> s32 #foreign libforms;

fl_winresize :: (win: Window, neww: FL_Coord, newh: FL_Coord) -> void #foreign libforms;

fl_winmove :: (win: Window, dx: FL_Coord, dy: FL_Coord) -> void #foreign libforms;

fl_winreshape :: (win: Window, dx: FL_Coord, dy: FL_Coord, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_winicon :: (win: Window, p: Pixmap, m: Pixmap) -> void #foreign libforms;

fl_winbackground :: (win: Window, bk: u64) -> void #foreign libforms;

fl_winstepsize :: (win: Window, dx: FL_Coord, dy: FL_Coord) -> void #foreign libforms;

fl_winisvalid :: (win: Window) -> s32 #foreign libforms;

fl_wintitle :: (win: Window, title: *u8) -> void #foreign libforms;

fl_wintitle_f_CFormat :: (win: Window, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_wintitle_f";
fl_wintitle_f :: (win: Window, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_wintitle_f_CFormat(win, "%s", formatted_text.data);
} @PrintLike

fl_winicontitle :: (win: Window, title: *u8) -> void #foreign libforms;

fl_winicontitle_f_CFormat :: (win: Window, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_winicontitle_f";
fl_winicontitle_f :: (win: Window, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_winicontitle_f_CFormat(win, "%s", formatted_text.data);
} @PrintLike

fl_winposition :: (x: FL_Coord, y: FL_Coord) -> void #foreign libforms;

fl_winminsize :: (win: Window, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_winmaxsize :: (win: Window, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_winaspect :: (win: Window, x: FL_Coord, y: FL_Coord) -> void #foreign libforms;

fl_reset_winconstraints :: (win: Window) -> void #foreign libforms;

fl_winsize :: (w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_initial_winsize :: (w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_initial_winstate :: (state: s32) -> void #foreign libforms;

fl_create_colormap :: (xv: *XVisualInfo, nfill: s32) -> Colormap #foreign libforms;

fl_wingeometry :: (x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_initial_wingeometry :: (x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_noborder :: () -> void #foreign libforms;

fl_transient :: () -> void #foreign libforms;

fl_get_winsize :: (win: Window, w: *FL_Coord, h: *FL_Coord) -> void #foreign libforms;

fl_get_winorigin :: (win: Window, x: *FL_Coord, y: *FL_Coord) -> void #foreign libforms;

fl_get_wingeometry :: (win: Window, x: *FL_Coord, y: *FL_Coord, w: *FL_Coord, h: *FL_Coord) -> void #foreign libforms;

fl_get_real_object_window :: (ob: *FL_OBJECT) -> Window #foreign libforms;

/* Replacements for X functions that access the event queue */
fl_XNextEvent :: (xev: *XEvent) -> s32 #foreign libforms;

fl_XPeekEvent :: (xev: *XEvent) -> s32 #foreign libforms;

fl_XEventsQueued :: (mode: s32) -> s32 #foreign libforms;

fl_XPutBackEvent :: (xev: *XEvent) -> void #foreign libforms;

fl_last_event :: () -> *XEvent #foreign libforms;

FL_APPEVENT_CB :: #type (unknown0: *XEvent, unknown1: *void) -> s32 #c_call;

fl_set_event_callback :: (callback: FL_APPEVENT_CB, user_data: *void) -> FL_APPEVENT_CB #foreign libforms;

fl_set_idle_callback :: (callback: FL_APPEVENT_CB, user_data: *void) -> FL_APPEVENT_CB #foreign libforms;

fl_addto_selected_xevent :: (win: Window, mask: s64) -> s64 #foreign libforms;

fl_remove_selected_xevent :: (win: Window, mask: s64) -> s64 #foreign libforms;

fl_set_idle_delta :: (delta: s64) -> void #foreign libforms;

fl_add_event_callback :: (win: Window, ev: s32, wincb: FL_APPEVENT_CB, user_data: *void) -> FL_APPEVENT_CB #foreign libforms;

fl_remove_event_callback :: (win: Window, ev: s32) -> void #foreign libforms;

fl_activate_event_callbacks :: (win: Window) -> void #foreign libforms;

fl_print_xevent_name :: (where: *u8, xev: *XEvent) -> *XEvent #foreign libforms;

fl_XFlush :: () -> void #foreign libforms;

/****************** Resources ***************/
FL_RTYPE :: enum u32 {
    NONE   :: 0;
    SHORT  :: 10;
    BOOL   :: 11;
    INT    :: 12;
    LONG   :: 13;
    FLOAT  :: 14;
    STRING :: 15;

    FL_NONE   :: NONE;
    FL_SHORT  :: SHORT;
    FL_BOOL   :: BOOL;
    FL_INT    :: INT;
    FL_LONG   :: LONG;
    FL_FLOAT  :: FLOAT;
    FL_STRING :: STRING;
}

FL_RESOURCE :: struct {
    res_name:  *u8; /* resource name                        */
    res_class: *u8; /* resource class                       */
    type:      FL_RTYPE; /* FL_INT, FL_FLOAT, FL_BOOL, FL_STRING */
    var:       *void; /* address for the variable             */
    defval:    *u8; /* default setting in string form       */
    nbytes:    s32; /* used only for strings                */
}

fl_initialize :: (na: *s32, arg: **u8, appclass: *u8, appopt: *XrmOptionDescRec, nappopt: s32) -> *Display #foreign libforms;

fl_finish :: () -> void #foreign libforms;

fl_get_resource :: (rname: *u8, cname: *u8, dtype: FL_RTYPE, defval: *u8, val: *void, size: s32) -> *u8 #foreign libforms;

fl_set_resource :: (str: *u8, val: *u8) -> void #foreign libforms;

fl_get_app_resources :: (appresource: *FL_RESOURCE, n: s32) -> void #foreign libforms;

fl_set_visualID :: (id: s64) -> void #foreign libforms;

fl_keysym_pressed :: (k: KeySym) -> s32 #foreign libforms;

/* All Form control variables. Named closely as its resource name */
FL_IOPT :: struct {
    rgamma:           float;
    ggamma:           float;
    bgamma:           float;
    debug:            s32;
    sync:             s32;
    depth:            s32;
    vclass:           s32;
    doubleBuffer:     s32;
    ulPropWidth:      s32; /* underline stuff       */
    ulThickness:      s32;
    buttonFontSize:   s32;
    sliderFontSize:   s32;
    inputFontSize:    s32;
    browserFontSize:  s32;
    menuFontSize:     s32;
    choiceFontSize:   s32;
    labelFontSize:    s32; /* all other labels fonts */
    pupFontSize:      s32; /* font for pop-up menus  */
    pupFontStyle:     s32;
    privateColormap:  s32;
    sharedColormap:   s32;
    standardColormap: s32;
    scrollbarType:    s32;
    backingStore:     s32;
    coordUnit:        s32;
    borderWidth:      s32;
    safe:             s32;
    rgbfile:          *u8; /* where RGB file is, not used */
    vname:            [24] u8;
}

/* Program default masks */
FL_9 :: enum u32 {
    PDDepth           :: 2;
    PDClass           :: 4;
    PDDouble          :: 8;
    PDSync            :: 16;
    PDPrivateMap      :: 32;
    PDScrollbarType   :: 64;
    PDPupFontSize     :: 128;
    PDButtonFontSize  :: 256;
    PDInputFontSize   :: 512;
    PDSliderFontSize  :: 1024;
    PDVisual          :: 2048;
    PDULThickness     :: 4096;
    PDULPropWidth     :: 8192;
    PDBS              :: 16384;
    PDCoordUnit       :: 32768;
    PDDebug           :: 65536;
    PDSharedMap       :: 131072;
    PDStandardMap     :: 262144;
    PDBorderWidth     :: 524288;
    PDSafe            :: 1048576;
    PDMenuFontSize    :: 2097152;
    PDBrowserFontSize :: 4194304;
    PDChoiceFontSize  :: 8388608;
    PDLabelFontSize   :: 16777216;

    FL_PDDepth           :: PDDepth;
    FL_PDClass           :: PDClass;
    FL_PDDouble          :: PDDouble;
    FL_PDSync            :: PDSync;
    FL_PDPrivateMap      :: PDPrivateMap;
    FL_PDScrollbarType   :: PDScrollbarType;
    FL_PDPupFontSize     :: PDPupFontSize;
    FL_PDButtonFontSize  :: PDButtonFontSize;
    FL_PDInputFontSize   :: PDInputFontSize;
    FL_PDSliderFontSize  :: PDSliderFontSize;
    FL_PDVisual          :: PDVisual;
    FL_PDULThickness     :: PDULThickness;
    FL_PDULPropWidth     :: PDULPropWidth;
    FL_PDBS              :: PDBS;
    FL_PDCoordUnit       :: PDCoordUnit;
    FL_PDDebug           :: PDDebug;
    FL_PDSharedMap       :: PDSharedMap;
    FL_PDStandardMap     :: PDStandardMap;
    FL_PDBorderWidth     :: PDBorderWidth;
    FL_PDSafe            :: PDSafe;
    FL_PDMenuFontSize    :: PDMenuFontSize;
    FL_PDBrowserFontSize :: PDBrowserFontSize;
    FL_PDChoiceFontSize  :: PDChoiceFontSize;
    FL_PDLabelFontSize   :: PDLabelFontSize;
}

fl_set_defaults :: (mask: u64, cntl: *FL_IOPT) -> void #foreign libforms;

fl_set_tabstop :: (s: *u8) -> void #foreign libforms;

fl_get_visual_depth :: () -> s32 #foreign libforms;

fl_is_global_clipped :: () -> s32 #foreign libforms;

fl_is_clipped :: (include_global: s32) -> s32 #foreign libforms;

fl_is_text_clipped :: (include_global: s32) -> s32 #foreign libforms;

fl_set_clipping :: (x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_unset_clipping :: () -> void #foreign libforms;

fl_set_text_clipping :: (x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_unset_text_clipping :: () -> void #foreign libforms;

fl_get_global_clipping :: (x: *FL_Coord, y: *FL_Coord, w: *FL_Coord, h: *FL_Coord) -> s32 #foreign libforms;

fl_get_clipping :: (include_global: s32, x: *FL_Coord, y: *FL_Coord, w: *FL_Coord, h: *FL_Coord) -> s32 #foreign libforms;

fl_get_text_clipping :: (include_global: s32, x: *FL_Coord, y: *FL_Coord, w: *FL_Coord, h: *FL_Coord) -> s32 #foreign libforms;

fl_set_gc_clipping :: (gc: GC, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord) -> void #foreign libforms;

fl_unset_gc_clipping :: (gc: GC) -> void #foreign libforms;

FL_PCTYPE :: u8;

FL_PACKED4 :: u32;

FL_RGB2PIXEL_ :: struct {
    rshift:        u32;
    rmask:         u32;
    rbits:         u32;
    gshift:        u32;
    gmask:         u32;
    gbits:         u32;
    bshift:        u32;
    bmask:         u32;
    bbits:         u32;
    bits_per_rgb:  s32;
    colormap_size: s32;
}

// FL_POPUP :: FL_POPUP_;
FL_POPUP_ENTRY :: FL_POPUP_ENTRY_;
FL_POPUP_RETURN :: FL_POPUP_RETURN_;

FL_POPUP_CB :: #type (unknown0: *FL_POPUP_RETURN) -> s32 #c_call;

FL_POPUP_RETURN_ :: struct {
    val:       s64; /* value assigned to popup entry */
    user_data: *void; /* pointer to user data */
    text:      *u8; /* text of the selected popup entry */
    label:     *u8; /* left-flushed label part */
    accel:     *u8; /* right-flushed label part */
    entry:     *FL_POPUP_ENTRY; /* pointer to selected popup entry */
    popup:     *FL_POPUP; /* popup we're called for */
}

FL_POPUP_ :: struct {
    next:             *FL_POPUP; /* next in linked list */
    prev:             *FL_POPUP; /* previous in linked list */
    parent:           *FL_POPUP; /* for sub-popups: direct parent */
    top_parent:       *FL_POPUP; /* and top-most parent */
    entries:          *FL_POPUP_ENTRY; /* pointer to list of entries */
    title:            *u8;
    win:              Window; /* popup window */
    parent_win:       Window; /* parent window of popup window */
    cursor:           Cursor; /* cursor for the popup */
    callback:         FL_POPUP_CB;
    use_req_pos:      s32; /* if set use req_x, req_y */
    req_x:            s32;
    req_y:            s32;
    x:                s32; /* position of popup window */
    y:                s32;
    w:                u32; /* dimensions of popup window */
    h:                u32;
    min_width:        s32; /* minimum width of popup */
    title_box_x:      s32; /* position of title box */
    title_box_y:      s32;
    title_box_w:      u32; /* dimensions of title box */
    title_box_h:      u32;
    has_subs:         s32;
    has_boxes:        s32;
    counter:          s32;
    title_font_style: s32;
    title_font_size:  s32;
    entry_font_style: s32;
    entry_font_size:  s32;
    event_mask:       u64;
    bw:               s32; /* border width */
    bg_color:         FL_COLOR; /* background color of popup*/
    on_color:         FL_COLOR; /* color of entry under mouse */
    title_color:      FL_COLOR; /* color of title text */
    text_color:       FL_COLOR; /* normal text color of entry */
    text_on_color:    FL_COLOR; /* text color when mouse on entry */
    text_off_color:   FL_COLOR; /* text color of disabled entry */
    radio_color:      FL_COLOR; /* color of radio buttons */
    policy:           s32;
    need_recalc:      s32; /* do we need to recalc position? */
    /* structure passed to calbacks
    and returned on selection */
    ret:              FL_POPUP_RETURN;
}

FL_POPUP_ENTRY_ :: struct {
    prev:           *FL_POPUP_ENTRY; /* next in linked list */
    next:           *FL_POPUP_ENTRY; /* previous in linked list */
    popup:          *FL_POPUP; /* popup it belongs to */
    is_act:         s32; /* set while mouse is over it */
    text:           *u8; /* complete text of entry */
    label:          *u8; /* cleaned-up label text */
    accel:          *u8; /* cleaned-up accelerator key text */
    val:            s64; /* value associated with entry */
    user_data:      *void; /* pointer to user data */
    type:           s32; /* normal, toggle, radio, sub-popup */
    state:          u32; /* disabled, hidden, checked */
    group:          s32; /* group (for radio entries only) */
    sub:            *FL_POPUP; /* sub-popup bound to entry */
    shortcut:       *s64; /* keyboard shortcuts */
    ulpos:          s32; /* underline position in text */
    callback:       FL_POPUP_CB; /* callback for entry */
    enter_callback: FL_POPUP_CB; /* callback for entering entry */
    leave_callback: FL_POPUP_CB; /* callback for leaving entry */
    x:              s32; /* position of entry text */
    y:              s32;
    w:              u32;
    h:              u32; /* height of entry text */
    box_x:          s32;
    box_y:          s32;
    box_w:          u32;
    box_h:          u32;
    sl_h:           u32;
    ul_x:           s32;
    ul_y:           s32;
    ul_w:           u32;
    ul_h:           u32;
}

FL_POPUP_ITEM :: struct {
    text:     *u8; /* text of entry */
    callback: FL_POPUP_CB; /* (selection) callback */
    shortcut: *u8; /* keyboard shortcut description */
    type:     s32; /* type of entry */
    state:    s32; /* disabled, hidden, checked */
}

/* Popup policies */
FL_POPUP :: enum u32 {
    NORMAL_SELECT :: 0;
    DRAG_SELECT   :: 1;

    FL_POPUP_NORMAL_SELECT :: NORMAL_SELECT;
    FL_POPUP_DRAG_SELECT   :: DRAG_SELECT;
}

/* Popup states */
FL_POPUP_1 :: enum u32 {
    NONE     :: 0;
    DISABLED :: 1;
    HIDDEN   :: 2;
    CHECKED  :: 4;

    FL_POPUP_NONE     :: NONE;
    FL_POPUP_DISABLED :: DISABLED;
    FL_POPUP_HIDDEN   :: HIDDEN;
    FL_POPUP_CHECKED  :: CHECKED;
}

/* Popup entry types */
FL_POPUP_2 :: enum u32 {
    NORMAL :: 0;
    TOGGLE :: 1;
    RADIO  :: 2;
    SUB    :: 3;
    LINE   :: 4;

    FL_POPUP_NORMAL :: NORMAL;
    FL_POPUP_TOGGLE :: TOGGLE;
    FL_POPUP_RADIO  :: RADIO;
    FL_POPUP_SUB    :: SUB;
    FL_POPUP_LINE   :: LINE;
}

/* Popup color types */
FL_POPUP_3 :: enum u32 {
    BACKGROUND_COLOR     :: 0;
    HIGHLIGHT_COLOR      :: 1;
    TITLE_COLOR          :: 2;
    TEXT_COLOR           :: 3;
    HIGHLIGHT_TEXT_COLOR :: 4;
    DISABLED_TEXT_COLOR  :: 5;
    RADIO_COLOR          :: 6;

    FL_POPUP_BACKGROUND_COLOR     :: BACKGROUND_COLOR;
    FL_POPUP_HIGHLIGHT_COLOR      :: HIGHLIGHT_COLOR;
    FL_POPUP_TITLE_COLOR          :: TITLE_COLOR;
    FL_POPUP_TEXT_COLOR           :: TEXT_COLOR;
    FL_POPUP_HIGHLIGHT_TEXT_COLOR :: HIGHLIGHT_TEXT_COLOR;
    FL_POPUP_DISABLED_TEXT_COLOR  :: DISABLED_TEXT_COLOR;
    FL_POPUP_RADIO_COLOR          :: RADIO_COLOR;
}

fl_popup_add :: (unknown0: Window, unknown1: *u8) -> *FL_POPUP #foreign libforms;

fl_popup_add_entries_CFormat :: (unknown0: *FL_POPUP, unknown1: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_popup_add_entries";
fl_popup_add_entries :: (unknown0: *FL_POPUP, unknown1: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown1, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_popup_add_entries_CFormat(unknown0, "%s", formatted_text.data);
} @PrintLike

fl_popup_insert_entries_CFormat :: (unknown0: *FL_POPUP, unknown1: *FL_POPUP_ENTRY, unknown2: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_popup_insert_entries";
fl_popup_insert_entries :: (unknown0: *FL_POPUP, unknown1: *FL_POPUP_ENTRY, unknown2: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown2, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_popup_insert_entries_CFormat(unknown0, unknown1, "%s", formatted_text.data);
} @PrintLike

fl_popup_create :: (unknown0: Window, unknown1: *u8, unknown2: *FL_POPUP_ITEM) -> *FL_POPUP #foreign libforms;

fl_popup_add_items :: (unknown0: *FL_POPUP, unknown1: *FL_POPUP_ITEM) -> *FL_POPUP_ENTRY #foreign libforms;

fl_popup_insert_items :: (unknown0: *FL_POPUP, unknown1: *FL_POPUP_ENTRY, unknown2: *FL_POPUP_ITEM) -> *FL_POPUP_ENTRY #foreign libforms;

fl_popup_delete :: (unknown0: *FL_POPUP) -> s32 #foreign libforms;

fl_popup_entry_delete :: (unknown0: *FL_POPUP_ENTRY) -> s32 #foreign libforms;

fl_popup_do :: (unknown0: *FL_POPUP) -> *FL_POPUP_RETURN #foreign libforms;

fl_popup_set_position :: (unknown0: *FL_POPUP, unknown1: s32, unknown2: s32) -> void #foreign libforms;

fl_popup_get_policy :: (unknown0: *FL_POPUP) -> s32 #foreign libforms;

fl_popup_set_policy :: (unknown0: *FL_POPUP, unknown1: s32) -> s32 #foreign libforms;

fl_popup_set_callback :: (unknown0: *FL_POPUP, unknown1: FL_POPUP_CB) -> FL_POPUP_CB #foreign libforms;

fl_popup_get_title_font :: (unknown0: *FL_POPUP, unknown1: *s32, unknown2: *s32) -> void #foreign libforms;

fl_popup_set_title_font :: (unknown0: *FL_POPUP, unknown1: s32, unknown2: s32) -> void #foreign libforms;

fl_popup_entry_get_font :: (unknown0: *FL_POPUP, unknown1: *s32, unknown2: *s32) -> void #foreign libforms;

fl_popup_entry_set_font :: (unknown0: *FL_POPUP, unknown1: s32, unknown2: s32) -> void #foreign libforms;

fl_popup_get_bw :: (unknown0: *FL_POPUP) -> s32 #foreign libforms;

fl_popup_set_bw :: (unknown0: *FL_POPUP, unknown1: s32) -> s32 #foreign libforms;

fl_popup_get_color :: (unknown0: *FL_POPUP, unknown1: s32) -> FL_COLOR #foreign libforms;

fl_popup_set_color :: (unknown0: *FL_POPUP, unknown1: s32, unknown2: FL_COLOR) -> FL_COLOR #foreign libforms;

fl_popup_set_cursor :: (unknown0: *FL_POPUP, unknown1: s32) -> void #foreign libforms;

fl_popup_get_title :: (unknown0: *FL_POPUP) -> *u8 #foreign libforms;

fl_popup_set_title :: (unknown0: *FL_POPUP, unknown1: *u8) -> *FL_POPUP #foreign libforms;

fl_popup_set_title_f_CFormat :: (popup: *FL_POPUP, fmt: *u8, __args: ..Any) -> *FL_POPUP #foreign libforms "fl_popup_set_title_f";
fl_popup_set_title_f :: (popup: *FL_POPUP, fmt: string, __args: ..Any) -> *FL_POPUP {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_popup_set_title_f_CFormat(popup, "%s", formatted_text.data);
} @PrintLike

fl_popup_entry_set_callback :: (unknown0: *FL_POPUP_ENTRY, unknown1: FL_POPUP_CB) -> FL_POPUP_CB #foreign libforms;

fl_popup_entry_set_enter_callback :: (unknown0: *FL_POPUP_ENTRY, unknown1: FL_POPUP_CB) -> FL_POPUP_CB #foreign libforms;

fl_popup_entry_set_leave_callback :: (unknown0: *FL_POPUP_ENTRY, unknown1: FL_POPUP_CB) -> FL_POPUP_CB #foreign libforms;

fl_popup_entry_get_state :: (unknown0: *FL_POPUP_ENTRY) -> u32 #foreign libforms;

fl_popup_entry_set_state :: (unknown0: *FL_POPUP_ENTRY, unknown1: u32) -> u32 #foreign libforms;

fl_popup_entry_clear_state :: (unknown0: *FL_POPUP_ENTRY, unknown1: u32) -> u32 #foreign libforms;

fl_popup_entry_raise_state :: (unknown0: *FL_POPUP_ENTRY, unknown1: u32) -> u32 #foreign libforms;

fl_popup_entry_toggle_state :: (unknown0: *FL_POPUP_ENTRY, unknown1: u32) -> u32 #foreign libforms;

fl_popup_entry_set_text :: (unknown0: *FL_POPUP_ENTRY, unknown1: *u8) -> s32 #foreign libforms;

fl_popup_entry_set_shortcut :: (unknown0: *FL_POPUP_ENTRY, unknown1: *u8) -> void #foreign libforms;

fl_popup_entry_set_value :: (unknown0: *FL_POPUP_ENTRY, unknown1: s64) -> s64 #foreign libforms;

fl_popup_entry_set_user_data :: (unknown0: *FL_POPUP_ENTRY, unknown1: *void) -> *void #foreign libforms;

fl_popup_entry_get_by_position :: (unknown0: *FL_POPUP, unknown1: s32) -> *FL_POPUP_ENTRY #foreign libforms;

fl_popup_entry_get_by_value :: (unknown0: *FL_POPUP, unknown1: s64) -> *FL_POPUP_ENTRY #foreign libforms;

fl_popup_entry_get_by_user_data :: (unknown0: *FL_POPUP, unknown1: *void) -> *FL_POPUP_ENTRY #foreign libforms;

fl_popup_entry_get_by_text :: (unknown0: *FL_POPUP, unknown1: *u8) -> *FL_POPUP_ENTRY #foreign libforms;

fl_popup_entry_get_by_text_f_CFormat :: (unknown0: *FL_POPUP, unknown1: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_popup_entry_get_by_text_f";
fl_popup_entry_get_by_text_f :: (unknown0: *FL_POPUP, unknown1: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown1, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_popup_entry_get_by_text_f_CFormat(unknown0, "%s", formatted_text.data);
} @PrintLike

fl_popup_entry_get_by_label :: (unknown0: *FL_POPUP, unknown1: *u8) -> *FL_POPUP_ENTRY #foreign libforms;

fl_popup_entry_get_by_label_f_CFormat :: (unknown0: *FL_POPUP, unknown1: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_popup_entry_get_by_label_f";
fl_popup_entry_get_by_label_f :: (unknown0: *FL_POPUP, unknown1: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown1, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_popup_entry_get_by_label_f_CFormat(unknown0, "%s", formatted_text.data);
} @PrintLike

fl_popup_entry_get_group :: (unknown0: *FL_POPUP_ENTRY) -> s32 #foreign libforms;

fl_popup_entry_set_group :: (unknown0: *FL_POPUP_ENTRY, unknown1: s32) -> s32 #foreign libforms;

fl_popup_entry_get_subpopup :: (unknown0: *FL_POPUP_ENTRY) -> *FL_POPUP #foreign libforms;

fl_popup_entry_set_subpopup :: (unknown0: *FL_POPUP_ENTRY, unknown1: *FL_POPUP) -> *FL_POPUP #foreign libforms;

fl_popup_get_size :: (unknown0: *FL_POPUP, unknown1: *u32, unknown2: *u32) -> s32 #foreign libforms;

fl_popup_get_min_width :: (unknown0: *FL_POPUP) -> s32 #foreign libforms;

fl_popup_set_min_width :: (unknown0: *FL_POPUP, unknown1: s32) -> s32 #foreign libforms;

/***** Routines *****/
fl_create_bitmap :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_bitmap :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_bitmap_data :: (ob: *FL_OBJECT, w: s32, h: s32, data: *u8) -> void #foreign libforms;

fl_set_bitmap_file :: (ob: *FL_OBJECT, fname: *u8) -> void #foreign libforms;

fl_read_bitmapfile :: (win: Window, file: *u8, w: *u32, h: *u32, hotx: *s32, hoty: *s32) -> Pixmap #foreign libforms;

fl_create_from_bitmapdata :: (win: Window, data: *u8, width: s32, height: s32) -> Pixmap #foreign libforms;

fl_create_pixmap :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_pixmap :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_pixmap_data :: (ob: *FL_OBJECT, bits: **u8) -> void #foreign libforms;

fl_set_pixmap_file :: (ob: *FL_OBJECT, fname: *u8) -> void #foreign libforms;

fl_set_pixmap_align :: (ob: *FL_OBJECT, align: s32, xmargin: s32, ymargin: s32) -> void #foreign libforms;

fl_set_pixmap_pixmap :: (ob: *FL_OBJECT, id: Pixmap, mask: Pixmap) -> void #foreign libforms;

fl_set_pixmap_colorcloseness :: (red: s32, green: s32, blue: s32) -> void #foreign libforms;

fl_free_pixmap_pixmap :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_free_pixmap_focus_pixmap :: (obj: *FL_OBJECT) -> void #foreign libforms;

fl_get_pixmap_pixmap :: (ob: *FL_OBJECT, p: *Pixmap, m: *Pixmap) -> Pixmap #foreign libforms;

fl_read_pixmapfile :: (win: Window, file: *u8, w: *u32, h: *u32, shape_mask: *Pixmap, hotx: *s32, hoty: *s32, tran: FL_COLOR) -> Pixmap #foreign libforms;

fl_create_from_pixmapdata :: (win: Window, data: **u8, w: *u32, h: *u32, sm: *Pixmap, hotx: *s32, hoty: *s32, tran: FL_COLOR) -> Pixmap #foreign libforms;

fl_free_pixmap :: (id: Pixmap) -> void #foreign libforms;

/* Type is already defined in Basic.h */
fl_create_box :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_box :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

/***** Types    *****/
FL_BROWSER_TYPE :: enum u32 {
    NORMAL_BROWSER            :: 0;
    SELECT_BROWSER            :: 1;
    HOLD_BROWSER              :: 2;
    MULTI_BROWSER             :: 3;
    DESELECTABLE_HOLD_BROWSER :: 4;

    FL_NORMAL_BROWSER            :: NORMAL_BROWSER;
    FL_SELECT_BROWSER            :: SELECT_BROWSER;
    FL_HOLD_BROWSER              :: HOLD_BROWSER;
    FL_MULTI_BROWSER             :: MULTI_BROWSER;
    FL_DESELECTABLE_HOLD_BROWSER :: DESELECTABLE_HOLD_BROWSER;
}

/***** Routines *****/
fl_create_browser :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_browser :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_clear_browser :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_add_browser_line :: (ob: *FL_OBJECT, newtext: *u8) -> void #foreign libforms;

fl_add_browser_line_f_CFormat :: (ob: *FL_OBJECT, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_add_browser_line_f";
fl_add_browser_line_f :: (ob: *FL_OBJECT, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_add_browser_line_f_CFormat(ob, "%s", formatted_text.data);
} @PrintLike

fl_addto_browser :: (obj: *FL_OBJECT, text: *u8) -> void #foreign libforms;

fl_addto_browser_f_CFormat :: (obj: *FL_OBJECT, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_addto_browser_f";
fl_addto_browser_f :: (obj: *FL_OBJECT, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_addto_browser_f_CFormat(obj, "%s", formatted_text.data);
} @PrintLike

fl_addto_browser_chars :: (ob: *FL_OBJECT, str: *u8) -> void #foreign libforms;

fl_addto_browser_chars_f_CFormat :: (ob: *FL_OBJECT, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_addto_browser_chars_f";
fl_addto_browser_chars_f :: (ob: *FL_OBJECT, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_addto_browser_chars_f_CFormat(ob, "%s", formatted_text.data);
} @PrintLike

fl_insert_browser_line :: (ob: *FL_OBJECT, linenumb: s32, newtext: *u8) -> void #foreign libforms;

fl_insert_browser_line_f_CFormat :: (ob: *FL_OBJECT, linenumb: s32, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_insert_browser_line_f";
fl_insert_browser_line_f :: (ob: *FL_OBJECT, linenumb: s32, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_insert_browser_line_f_CFormat(ob, linenumb, "%s", formatted_text.data);
} @PrintLike

fl_delete_browser_line :: (ob: *FL_OBJECT, linenumb: s32) -> void #foreign libforms;

fl_replace_browser_line :: (ob: *FL_OBJECT, linenumb: s32, newtext: *u8) -> void #foreign libforms;

fl_replace_browser_line_f_CFormat :: (ob: *FL_OBJECT, linenumb: s32, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_replace_browser_line_f";
fl_replace_browser_line_f :: (ob: *FL_OBJECT, linenumb: s32, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_replace_browser_line_f_CFormat(ob, linenumb, "%s", formatted_text.data);
} @PrintLike

fl_get_browser_line :: (ob: *FL_OBJECT, linenumb: s32) -> *u8 #foreign libforms;

fl_load_browser :: (ob: *FL_OBJECT, filename: *u8) -> s32 #foreign libforms;

fl_select_browser_line :: (ob: *FL_OBJECT, line: s32) -> void #foreign libforms;

fl_deselect_browser_line :: (ob: *FL_OBJECT, line: s32) -> void #foreign libforms;

fl_deselect_browser :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_isselected_browser_line :: (ob: *FL_OBJECT, line: s32) -> s32 #foreign libforms;

fl_get_browser_topline :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_browser :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_browser_maxline :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_browser_screenlines :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_browser_topline :: (ob: *FL_OBJECT, line: s32) -> void #foreign libforms;

fl_set_browser_bottomline :: (ob: *FL_OBJECT, line: s32) -> void #foreign libforms;

fl_set_browser_fontsize :: (ob: *FL_OBJECT, size: s32) -> void #foreign libforms;

fl_set_browser_fontstyle :: (ob: *FL_OBJECT, style: s32) -> void #foreign libforms;

fl_set_browser_specialkey :: (ob: *FL_OBJECT, specialkey: s32) -> void #foreign libforms;

fl_set_browser_vscrollbar :: (ob: *FL_OBJECT, on: s32) -> void #foreign libforms;

fl_set_browser_hscrollbar :: (ob: *FL_OBJECT, on: s32) -> void #foreign libforms;

fl_set_browser_line_selectable :: (ob: *FL_OBJECT, line: s32, flag: s32) -> void #foreign libforms;

fl_get_browser_dimension :: (ob: *FL_OBJECT, x: *FL_Coord, y: *FL_Coord, w: *FL_Coord, h: *FL_Coord) -> void #foreign libforms;

fl_set_browser_dblclick_callback :: (ob: *FL_OBJECT, cb: FL_CALLBACKPTR, a: s64) -> void #foreign libforms;

fl_get_browser_xoffset :: (ob: *FL_OBJECT) -> FL_Coord #foreign libforms;

fl_get_browser_rel_xoffset :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_browser_xoffset :: (ob: *FL_OBJECT, npixels: FL_Coord) -> void #foreign libforms;

fl_set_browser_rel_xoffset :: (ob: *FL_OBJECT, val: float64) -> void #foreign libforms;

fl_get_browser_yoffset :: (ob: *FL_OBJECT) -> FL_Coord #foreign libforms;

fl_get_browser_rel_yoffset :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_browser_yoffset :: (ob: *FL_OBJECT, npixels: FL_Coord) -> void #foreign libforms;

fl_set_browser_rel_yoffset :: (ob: *FL_OBJECT, val: float64) -> void #foreign libforms;

fl_set_browser_scrollbarsize :: (ob: *FL_OBJECT, hh: s32, vw: s32) -> void #foreign libforms;

fl_show_browser_line :: (ob: *FL_OBJECT, j: s32) -> void #foreign libforms;

fl_set_default_browser_maxlinelength :: (n: s32) -> s32 #foreign libforms;

FL_BROWSER_SCROLL_CALLBACK :: #type (unknown0: *FL_OBJECT, unknown1: s32, unknown2: *void) -> void #c_call;

fl_set_browser_hscroll_callback :: (unknown0: *FL_OBJECT, unknown1: FL_BROWSER_SCROLL_CALLBACK, unknown2: *void) -> void #foreign libforms;

fl_set_browser_vscroll_callback :: (unknown0: *FL_OBJECT, unknown1: FL_BROWSER_SCROLL_CALLBACK, unknown2: *void) -> void #foreign libforms;

fl_get_browser_line_yoffset :: (unknown0: *FL_OBJECT, unknown1: s32) -> s32 #foreign libforms;

fl_get_browser_hscroll_callback :: (unknown0: *FL_OBJECT) -> FL_BROWSER_SCROLL_CALLBACK #foreign libforms;

fl_get_browser_vscroll_callback :: (unknown0: *FL_OBJECT) -> FL_BROWSER_SCROLL_CALLBACK #foreign libforms;

fl_get_browser_scrollbar_repeat :: (unknown0: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_browser_scrollbar_repeat :: (unknown0: *FL_OBJECT, unknown1: s32) -> void #foreign libforms;

FL_BUTTON_TYPE :: enum u32 {
    NORMAL_BUTTON     :: 0;
    PUSH_BUTTON       :: 1;
    RADIO_BUTTON      :: 2;
    HIDDEN_BUTTON     :: 3;
    TOUCH_BUTTON      :: 4;
    INOUT_BUTTON      :: 5;
    RETURN_BUTTON     :: 6;
    HIDDEN_RET_BUTTON :: 7;
    MENU_BUTTON       :: 8;

    FL_NORMAL_BUTTON     :: NORMAL_BUTTON;
    FL_PUSH_BUTTON       :: PUSH_BUTTON;
    FL_RADIO_BUTTON      :: RADIO_BUTTON;
    FL_HIDDEN_BUTTON     :: HIDDEN_BUTTON;
    FL_TOUCH_BUTTON      :: TOUCH_BUTTON;
    FL_INOUT_BUTTON      :: INOUT_BUTTON;
    FL_RETURN_BUTTON     :: RETURN_BUTTON;
    FL_HIDDEN_RET_BUTTON :: HIDDEN_RET_BUTTON;
    FL_MENU_BUTTON       :: MENU_BUTTON;
}

FL_BUTTON_SPEC :: struct {
    pixmap:         Pixmap;
    mask:           Pixmap;
    bits_w:         u32;
    bits_h:         u32;
    val:            s32; /* state of button (on/off) */
    mousebut:       s32; /* mouse button that caused the push     */
    timdel:         s32; /* time since last touch (TOUCH buttons) */
    event:          s32; /* what event triggers redraw            */
    is_pushed:      s32; /* set while drawn as pushed down        */
    react_to:       [5] s32; /* mouse buttons button reacts to        */
    cspecl:         s64; /* reserved for class specfic stuff      */
    cspecv:         *void; /* misc. things                          */
    filename:       *u8;
    focus_pixmap:   Pixmap;
    focus_mask:     Pixmap;
    focus_filename: *u8;
}

FL_DrawButton :: #type (unknown0: *FL_OBJECT) -> void #c_call;
FL_CleanupButton :: #type (unknown0: *FL_BUTTON_SPEC) -> void #c_call;

/***** Routines *****/
fl_create_button :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_create_roundbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_create_round3dbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_create_lightbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_create_checkbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_create_bitmapbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_create_pixmapbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_create_scrollbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_create_labelbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_roundbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_round3dbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_lightbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_checkbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_button :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_bitmapbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_scrollbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_labelbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_bitmapbutton_data :: (ob: *FL_OBJECT, w: s32, h: s32, bits: *u8) -> void #foreign libforms;

fl_add_pixmapbutton :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_pixmapbutton_focus_outline :: (ob: *FL_OBJECT, yes: s32) -> void #foreign libforms;

fl_set_pixmapbutton_focus_data :: (ob: *FL_OBJECT, bits: **u8) -> void #foreign libforms;

fl_set_pixmapbutton_focus_file :: (ob: *FL_OBJECT, fname: *u8) -> void #foreign libforms;

fl_set_pixmapbutton_focus_pixmap :: (ob: *FL_OBJECT, id: Pixmap, mask: Pixmap) -> void #foreign libforms;

fl_get_button :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_button :: (ob: *FL_OBJECT, pushed: s32) -> void #foreign libforms;

fl_get_button_numb :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_create_generic_button :: (objclass: s32, type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_button_class :: (bclass: s32, drawit: FL_DrawButton, cleanup: FL_CleanupButton) -> void #foreign libforms;

fl_set_button_mouse_buttons :: (ob: *FL_OBJECT, buttons: u32) -> void #foreign libforms;

fl_get_button_mouse_buttons :: (ob: *FL_OBJECT, buttons: *u32) -> void #foreign libforms;

FL_CANVAS_TYPE :: enum u32 {
    NORMAL_CANVAS   :: 0;
    SCROLLED_CANVAS :: 1;

    FL_NORMAL_CANVAS   :: NORMAL_CANVAS;
    FL_SCROLLED_CANVAS :: SCROLLED_CANVAS;
}

FL_HANDLE_CANVAS :: #type (unknown0: *FL_OBJECT, unknown1: Window, unknown2: s32, unknown3: s32, unknown4: *XEvent, unknown5: *void) -> s32 #c_call;

FL_MODIFY_CANVAS_PROP :: #type (unknown0: *FL_OBJECT) -> s32 #c_call;

/************ Interfaces    ************************/
fl_create_generic_canvas :: (canvas_class: s32, type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_canvas :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_create_canvas :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_canvas_colormap :: (ob: *FL_OBJECT, colormap: Colormap) -> void #foreign libforms;

fl_set_canvas_visual :: (obj: *FL_OBJECT, vi: *Visual) -> void #foreign libforms;

fl_set_canvas_depth :: (obj: *FL_OBJECT, depth: s32) -> void #foreign libforms;

fl_set_canvas_attributes :: (ob: *FL_OBJECT, mask: u32, xswa: *XSetWindowAttributes) -> void #foreign libforms;

fl_add_canvas_handler :: (ob: *FL_OBJECT, ev: s32, h: FL_HANDLE_CANVAS, udata: *void) -> FL_HANDLE_CANVAS #foreign libforms;

fl_get_canvas_id :: (ob: *FL_OBJECT) -> Window #foreign libforms;

fl_get_canvas_colormap :: (ob: *FL_OBJECT) -> Colormap #foreign libforms;

fl_get_canvas_depth :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_remove_canvas_handler :: (ob: *FL_OBJECT, ev: s32, h: FL_HANDLE_CANVAS) -> void #foreign libforms;

fl_share_canvas_colormap :: (ob: *FL_OBJECT, colormap: Colormap) -> void #foreign libforms;

fl_clear_canvas :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_modify_canvas_prop :: (obj: *FL_OBJECT, init: FL_MODIFY_CANVAS_PROP, activate: FL_MODIFY_CANVAS_PROP, cleanup: FL_MODIFY_CANVAS_PROP) -> void #foreign libforms;

fl_canvas_yield_to_shortcut :: (ob: *FL_OBJECT, yes: s32) -> void #foreign libforms;

FL_CHART_TYPE :: enum u32 {
    BAR_CHART        :: 0;
    HORBAR_CHART     :: 1;
    LINE_CHART       :: 2;
    FILL_CHART       :: 3;
    SPIKE_CHART      :: 4;
    PIE_CHART        :: 5;
    SPECIALPIE_CHART :: 6;

    FL_BAR_CHART        :: BAR_CHART;
    FL_HORBAR_CHART     :: HORBAR_CHART;
    FL_LINE_CHART       :: LINE_CHART;
    FL_FILL_CHART       :: FILL_CHART;
    FL_SPIKE_CHART      :: SPIKE_CHART;
    FL_PIE_CHART        :: PIE_CHART;
    FL_SPECIALPIE_CHART :: SPECIALPIE_CHART;
}

/***** Routines *****/
fl_create_chart :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_chart :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_clear_chart :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_add_chart_value :: (ob: *FL_OBJECT, val: float64, str: *u8, col: FL_COLOR) -> void #foreign libforms;

fl_insert_chart_value :: (ob: *FL_OBJECT, indx: s32, val: float64, str: *u8, col: FL_COLOR) -> void #foreign libforms;

fl_replace_chart_value :: (ob: *FL_OBJECT, indx: s32, val: float64, str: *u8, col: FL_COLOR) -> void #foreign libforms;

fl_set_chart_bounds :: (ob: *FL_OBJECT, min: float64, max: float64) -> void #foreign libforms;

fl_get_chart_bounds :: (ob: *FL_OBJECT, min: *float64, max: *float64) -> void #foreign libforms;

fl_set_chart_maxnumb :: (ob: *FL_OBJECT, maxnumb: s32) -> void #foreign libforms;

fl_set_chart_autosize :: (ob: *FL_OBJECT, autosize: s32) -> void #foreign libforms;

fl_set_chart_lstyle :: (ob: *FL_OBJECT, lstyle: s32) -> void #foreign libforms;

fl_set_chart_lsize :: (ob: *FL_OBJECT, lsize: s32) -> void #foreign libforms;

fl_set_chart_lcolor :: (ob: *FL_OBJECT, lcol: FL_COLOR) -> void #foreign libforms;

fl_set_chart_baseline :: (ob: *FL_OBJECT, iYesNo: s32) -> void #foreign libforms;

FL_CHOICE_TYPE :: enum u32 {
    NORMAL_CHOICE   :: 0;
    NORMAL_CHOICE2  :: 1;
    DROPLIST_CHOICE :: 2;
    BROWSER_CHOICE  :: 3;

    FL_NORMAL_CHOICE   :: NORMAL_CHOICE;
    FL_NORMAL_CHOICE2  :: NORMAL_CHOICE2;
    FL_DROPLIST_CHOICE :: DROPLIST_CHOICE;
    FL_BROWSER_CHOICE  :: BROWSER_CHOICE;
}

/***** Routines *****/
fl_create_choice :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_choice :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_clear_choice :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_addto_choice :: (ob: *FL_OBJECT, str: *u8) -> s32 #foreign libforms;

fl_addto_choice_f_CFormat :: (ob: *FL_OBJECT, fmt: *u8, __args: ..Any) -> s32 #foreign libforms "fl_addto_choice_f";
fl_addto_choice_f :: (ob: *FL_OBJECT, fmt: string, __args: ..Any) -> s32 {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_addto_choice_f_CFormat(ob, "%s", formatted_text.data);
} @PrintLike

fl_replace_choice :: (ob: *FL_OBJECT, numb: s32, str: *u8) -> void #foreign libforms;

fl_replace_choice_f_CFormat :: (ob: *FL_OBJECT, numb: s32, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_replace_choice_f";
fl_replace_choice_f :: (ob: *FL_OBJECT, numb: s32, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_replace_choice_f_CFormat(ob, numb, "%s", formatted_text.data);
} @PrintLike

fl_delete_choice :: (ob: *FL_OBJECT, numb: s32) -> void #foreign libforms;

fl_set_choice :: (ob: *FL_OBJECT, choice: s32) -> void #foreign libforms;

fl_set_choice_text :: (ob: *FL_OBJECT, txt: *u8) -> void #foreign libforms;

fl_set_choice_text_f_CFormat :: (ob: *FL_OBJECT, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_set_choice_text_f";
fl_set_choice_text_f :: (ob: *FL_OBJECT, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_set_choice_text_f_CFormat(ob, "%s", formatted_text.data);
} @PrintLike

fl_get_choice :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_choice_item_text :: (ob: *FL_OBJECT, n: s32) -> *u8 #foreign libforms;

fl_get_choice_maxitems :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_choice_text :: (ob: *FL_OBJECT) -> *u8 #foreign libforms;

fl_set_choice_fontsize :: (ob: *FL_OBJECT, size: s32) -> void #foreign libforms;

fl_set_choice_fontstyle :: (ob: *FL_OBJECT, style: s32) -> void #foreign libforms;

fl_set_choice_align :: (ob: *FL_OBJECT, align: s32) -> void #foreign libforms;

fl_get_choice_item_mode :: (ob: *FL_OBJECT, item: s32) -> s32 #foreign libforms;

fl_set_choice_item_mode :: (ob: *FL_OBJECT, item: s32, mode: u32) -> void #foreign libforms;

fl_set_choice_item_shortcut :: (ob: *FL_OBJECT, item: s32, sc: *u8) -> void #foreign libforms;

fl_set_choice_entries :: (ob: *FL_OBJECT, ent: *FL_PUP_ENTRY) -> s32 #foreign libforms;

fl_set_choice_notitle :: (ob: *FL_OBJECT, n: s32) -> s32 #foreign libforms;

fl_set_choice_align_bottom :: (ob: *FL_OBJECT, n: s32) -> s32 #foreign libforms;

FL_CPTYPE :: Atom;

FL_LOSE_SELECTION_CB :: #type (unknown0: *FL_OBJECT, unknown1: s64) -> s32 #c_call;
FL_SELECTION_CB :: #type (unknown0: *FL_OBJECT, unknown1: s64, unknown2: *void, unknown3: s64) -> s32 #c_call;

fl_stuff_clipboard :: (ob: *FL_OBJECT, type: s64, data: *void, size: s64, lose_callback: FL_LOSE_SELECTION_CB) -> s32 #foreign libforms;

fl_request_clipboard :: (ob: *FL_OBJECT, type: s64, got_it_callback: FL_SELECTION_CB) -> s32 #foreign libforms;

FL_10 :: enum u32 {
    ANALOG_CLOCK  :: 0;
    DIGITAL_CLOCK :: 1;

    FL_ANALOG_CLOCK  :: ANALOG_CLOCK;
    FL_DIGITAL_CLOCK :: DIGITAL_CLOCK;
}

fl_create_clock :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, s: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_clock :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, s: *u8) -> *FL_OBJECT #foreign libforms;

fl_get_clock :: (ob: *FL_OBJECT, h: *s32, m: *s32, s: *s32) -> void #foreign libforms;

fl_set_clock_adjustment :: (ob: *FL_OBJECT, offset: s64) -> s64 #foreign libforms;

fl_set_clock_ampm :: (ob: *FL_OBJECT, y: s32) -> void #foreign libforms;

FL_COUNTER_TYPE :: enum u32 {
    NORMAL_COUNTER :: 0;
    SIMPLE_COUNTER :: 1;

    FL_NORMAL_COUNTER :: NORMAL_COUNTER;
    FL_SIMPLE_COUNTER :: SIMPLE_COUNTER;
}

/***** Routines *****/
fl_create_counter :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_counter :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_counter_value :: (ob: *FL_OBJECT, val: float64) -> void #foreign libforms;

fl_set_counter_bounds :: (ob: *FL_OBJECT, min: float64, max: float64) -> void #foreign libforms;

fl_set_counter_step :: (ob: *FL_OBJECT, s: float64, l: float64) -> void #foreign libforms;

fl_set_counter_precision :: (ob: *FL_OBJECT, prec: s32) -> void #foreign libforms;

fl_get_counter_precision :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_counter_return :: (ob: *FL_OBJECT, how: u32) -> void #foreign libforms;

fl_get_counter_value :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_get_counter_bounds :: (ob: *FL_OBJECT, min: *float64, max: *float64) -> void #foreign libforms;

fl_get_counter_step :: (ob: *FL_OBJECT, s: *float64, l: *float64) -> void #foreign libforms;

fl_set_counter_filter :: (ob: *FL_OBJECT, filter: FL_VAL_FILTER) -> void #foreign libforms;

/* Functions to set and get the timeout value used by the
* counter code to control modification of the counter value. */
fl_get_counter_repeat :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_counter_repeat :: (ob: *FL_OBJECT, millisec: s32) -> void #foreign libforms;

fl_get_counter_min_repeat :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_counter_min_repeat :: (ob: *FL_OBJECT, millisec: s32) -> void #foreign libforms;

fl_get_counter_speedjump :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_counter_speedjump :: (ob: *FL_OBJECT, yes_no: s32) -> void #foreign libforms;

FL_11 :: enum s32 {
    INVISIBLE_CURSOR :: -2;
    DEFAULT_CURSOR   :: -1;
    BUSY_CURSOR      :: 150;
    CROSSHAIR_CURSOR :: 130;
    KILL_CURSOR      :: 88;
    NWARROW_CURSOR   :: 132;
    NEARROW_CURSOR   :: 2;

    FL_INVISIBLE_CURSOR :: INVISIBLE_CURSOR;
    FL_DEFAULT_CURSOR   :: DEFAULT_CURSOR;
    FL_BUSY_CURSOR      :: BUSY_CURSOR;
    FL_CROSSHAIR_CURSOR :: CROSSHAIR_CURSOR;
    FL_KILL_CURSOR      :: KILL_CURSOR;
    FL_NWARROW_CURSOR   :: NWARROW_CURSOR;
    FL_NEARROW_CURSOR   :: NEARROW_CURSOR;
}

fl_set_cursor :: (win: Window, name: s32) -> void #foreign libforms;

fl_set_cursor_color :: (name: s32, fg: FL_COLOR, bg: FL_COLOR) -> void #foreign libforms;

fl_create_bitmap_cursor :: (source: *u8, mask: *u8, w: s32, h: s32, hotx: s32, hoty: s32) -> s32 #foreign libforms;

fl_create_animated_cursor :: (cur_names: *s32, timeout: s32) -> s32 #foreign libforms;

FL_DIAL_TYPE :: enum u32 {
    NORMAL_DIAL :: 0;
    LINE_DIAL   :: 1;
    FILL_DIAL   :: 2;

    FL_NORMAL_DIAL :: NORMAL_DIAL;
    FL_LINE_DIAL   :: LINE_DIAL;
    FL_FILL_DIAL   :: FILL_DIAL;
}

FL_DIAL :: enum u32 {
    CW  :: 0;
    CCW :: 1;

    FL_DIAL_CW  :: CW;
    FL_DIAL_CCW :: CCW;
}

/***** Routines *****/
fl_create_dial :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_dial :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_dial_value :: (obj: *FL_OBJECT, val: float64) -> void #foreign libforms;

fl_get_dial_value :: (obj: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_dial_bounds :: (obj: *FL_OBJECT, min: float64, max: float64) -> void #foreign libforms;

fl_get_dial_bounds :: (obj: *FL_OBJECT, min: *float64, max: *float64) -> void #foreign libforms;

fl_set_dial_step :: (obj: *FL_OBJECT, value: float64) -> void #foreign libforms;

fl_get_dial_step :: (obj: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_dial_return :: (obj: *FL_OBJECT, value: u32) -> void #foreign libforms;

fl_set_dial_angles :: (obj: *FL_OBJECT, amin: float64, amax: float64) -> void #foreign libforms;

fl_get_dial_angles :: (obj: *FL_OBJECT, amin: *float64, amax: *float64) -> void #foreign libforms;

fl_set_dial_cross :: (obj: *FL_OBJECT, flag: s32) -> void #foreign libforms;

fl_set_dial_direction :: (obj: *FL_OBJECT, dir: s32) -> void #foreign libforms;

fl_get_dial_direction :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

/*  File types */
FT :: enum u32 {
    FILE  :: 0;
    DIR   :: 1;
    LINK  :: 2;
    SOCK  :: 3;
    FIFO  :: 4;
    BLK   :: 5;
    CHR   :: 6;
    OTHER :: 7;

    FT_FILE  :: FILE;
    FT_DIR   :: DIR;
    FT_LINK  :: LINK;
    FT_SOCK  :: SOCK;
    FT_FIFO  :: FIFO;
    FT_BLK   :: BLK;
    FT_CHR   :: CHR;
    FT_OTHER :: OTHER;
}

FL_Dirlist :: struct {
    name:     *u8; /* entry name             */
    type:     s32; /* FILE_TYPE              */
    dl_mtime: s64; /* file modification time */
    dl_size:  u64; /* file size in bytes     */
}

FL_12 :: enum u32 {
    ALPHASORT      :: 1;
    RALPHASORT     :: 2;
    MTIMESORT      :: 3;
    RMTIMESORT     :: 4;
    SIZESORT       :: 5;
    RSIZESORT      :: 6;
    CASEALPHASORT  :: 7;
    RCASEALPHASORT :: 8;

    FL_ALPHASORT      :: ALPHASORT;
    FL_RALPHASORT     :: RALPHASORT;
    FL_MTIMESORT      :: MTIMESORT;
    FL_RMTIMESORT     :: RMTIMESORT;
    FL_SIZESORT       :: SIZESORT;
    FL_RSIZESORT      :: RSIZESORT;
    FL_CASEALPHASORT  :: CASEALPHASORT;
    FL_RCASEALPHASORT :: RCASEALPHASORT;
}

FL_DIRLIST_FILTER :: #type (unknown0: *u8, unknown1: s32) -> s32 #c_call;

/* read dir with pattern filtering. All dirs read might be cached.
* Must not change dirlist in anyway. */
fl_get_dirlist :: (dir: *u8, pattern: *u8, n: *s32, rescan: s32) -> *FL_Dirlist #foreign libforms;

fl_set_dirlist_filter :: (filter: FL_DIRLIST_FILTER) -> FL_DIRLIST_FILTER #foreign libforms;

fl_set_dirlist_sort :: (method: s32) -> s32 #foreign libforms;

fl_set_dirlist_filterdir :: (yes: s32) -> s32 #foreign libforms;

fl_free_dirlist :: (dl: *FL_Dirlist) -> void #foreign libforms;

/* postscript stuff */
FLPS :: enum u32 {
    AUTO      :: 0;
    LANDSCAPE :: 1;
    PORTRAIT  :: 2;
    BESTFIT   :: 3;

    FLPS_AUTO      :: AUTO;
    FLPS_LANDSCAPE :: LANDSCAPE;
    FLPS_PORTRAIT  :: PORTRAIT;
    FLPS_BESTFIT   :: BESTFIT;
}

FLPS_1 :: enum s32 {
    BW        :: -1;
    GRAYSCALE :: 0;
    COLOR     :: 1;

    FLPS_BW        :: BW;
    FLPS_GRAYSCALE :: GRAYSCALE;
    FLPS_COLOR     :: COLOR;
}

FLPS_CONTROL :: struct {
    ps_color:        s32;
    orientation:     s32;
    auto_fit:        s32;
    drawbox:         s32;
    eps:             s32;
    xdpi:            float;
    ydpi:            float;
    paper_w:         float;
    paper_h:         float;
    gamma:           float;
    tmpdir:          *u8;
    printer_dpi:     s32;
    hm:              float;
    vm:              float;
    xscale:          float;
    yscale:          float;
    scale_text:      s32;
    first_page_only: s32;
    clip:            s32;
}

anon_enum :: enum u32 {
    FL_NORMAL_FORMBROWSER :: 0;
}

FL_13 :: enum u32 {
    SMOOTH_SCROLL :: 0;
    JUMP_SCROLL   :: 1;

    FL_SMOOTH_SCROLL :: SMOOTH_SCROLL;
    FL_JUMP_SCROLL   :: JUMP_SCROLL;
}

fl_addto_formbrowser :: (ob: *FL_OBJECT, form: *FL_FORM) -> s32 #foreign libforms;

fl_delete_formbrowser_bynumber :: (ob: *FL_OBJECT, num: s32) -> *FL_FORM #foreign libforms;

fl_delete_formbrowser :: (ob: *FL_OBJECT, form: *FL_FORM) -> s32 #foreign libforms;

fl_replace_formbrowser :: (ob: *FL_OBJECT, num: s32, form: *FL_FORM) -> *FL_FORM #foreign libforms;

fl_insert_formbrowser :: (ob: *FL_OBJECT, line: s32, new_form: *FL_FORM) -> s32 #foreign libforms;

fl_get_formbrowser_area :: (ob: *FL_OBJECT, x: *s32, y: *s32, w: *s32, h: *s32) -> s32 #foreign libforms;

fl_set_formbrowser_scroll :: (ob: *FL_OBJECT, how: s32) -> void #foreign libforms;

fl_set_formbrowser_hscrollbar :: (ob: *FL_OBJECT, how: s32) -> void #foreign libforms;

fl_set_formbrowser_vscrollbar :: (ob: *FL_OBJECT, how: s32) -> void #foreign libforms;

fl_get_formbrowser_topform :: (ob: *FL_OBJECT) -> *FL_FORM #foreign libforms;

fl_set_formbrowser_topform :: (ob: *FL_OBJECT, form: *FL_FORM) -> s32 #foreign libforms;

fl_set_formbrowser_topform_bynumber :: (ob: *FL_OBJECT, n: s32) -> *FL_FORM #foreign libforms;

fl_set_formbrowser_xoffset :: (ob: *FL_OBJECT, offset: s32) -> s32 #foreign libforms;

fl_set_formbrowser_yoffset :: (ob: *FL_OBJECT, offset: s32) -> s32 #foreign libforms;

fl_get_formbrowser_xoffset :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_formbrowser_yoffset :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_find_formbrowser_form_number :: (ob: *FL_OBJECT, form: *FL_FORM) -> s32 #foreign libforms;

fl_add_formbrowser :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_create_formbrowser :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_get_formbrowser_numforms :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_formbrowser_form :: (ob: *FL_OBJECT, n: s32) -> *FL_FORM #foreign libforms;

/* types of frames */
FL_14 :: enum u32 {
    NO_FRAME       :: 0;
    UP_FRAME       :: 1;
    DOWN_FRAME     :: 2;
    BORDER_FRAME   :: 3;
    SHADOW_FRAME   :: 4;
    ENGRAVED_FRAME :: 5;
    ROUNDED_FRAME  :: 6;
    EMBOSSED_FRAME :: 7;
    OVAL_FRAME     :: 8;

    FL_NO_FRAME       :: NO_FRAME;
    FL_UP_FRAME       :: UP_FRAME;
    FL_DOWN_FRAME     :: DOWN_FRAME;
    FL_BORDER_FRAME   :: BORDER_FRAME;
    FL_SHADOW_FRAME   :: SHADOW_FRAME;
    FL_ENGRAVED_FRAME :: ENGRAVED_FRAME;
    FL_ROUNDED_FRAME  :: ROUNDED_FRAME;
    FL_EMBOSSED_FRAME :: EMBOSSED_FRAME;
    FL_OVAL_FRAME     :: OVAL_FRAME;
}

fl_create_frame :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_frame :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

/* labeld frame */
fl_create_labelframe :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_labelframe :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

FL_FREE_TYPE :: enum u32 {
    NORMAL_FREE     :: 0;
    INACTIVE_FREE   :: 1;
    INPUT_FREE      :: 2;
    CONTINUOUS_FREE :: 3;
    ALL_FREE        :: 4;

    FL_NORMAL_FREE     :: NORMAL_FREE;
    FL_INACTIVE_FREE   :: INACTIVE_FREE;
    FL_INPUT_FREE      :: INPUT_FREE;
    FL_CONTINUOUS_FREE :: CONTINUOUS_FREE;
    FL_ALL_FREE        :: ALL_FREE;
}

fl_create_free :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8, handle: FL_HANDLEPTR) -> *FL_OBJECT #foreign libforms;

fl_add_free :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8, handle: FL_HANDLEPTR) -> *FL_OBJECT #foreign libforms;

fl_set_goodies_font :: (style: s32, size: s32) -> void #foreign libforms;

/*********** messages and questions **************/
fl_show_message :: (unknown0: *u8, unknown1: *u8, unknown2: *u8) -> void #foreign libforms;

fl_show_messages :: (unknown0: *u8) -> void #foreign libforms;

fl_show_messages_f_CFormat :: (unknown0: *u8, __args: ..Any) -> void #foreign libforms "fl_show_messages_f";
fl_show_messages_f :: (unknown0: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown0, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_show_messages_f_CFormat("%s", formatted_text.data);
} @PrintLike

fl_hide_message :: () -> void #foreign libforms;

fl_show_question :: (unknown0: *u8, unknown1: s32) -> s32 #foreign libforms;

fl_hide_question :: () -> void #foreign libforms;

fl_show_alert :: (unknown0: *u8, unknown1: *u8, unknown2: *u8, unknown3: s32) -> void #foreign libforms;

fl_show_alert_f_CFormat :: (c: s32, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_show_alert_f";
fl_show_alert_f :: (c: s32, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_show_alert_f_CFormat(c, "%s", formatted_text.data);
} @PrintLike

fl_hide_alert :: () -> void #foreign libforms;

fl_show_input :: (unknown0: *u8, unknown1: *u8) -> *u8 #foreign libforms;

fl_hide_input :: () -> void #foreign libforms;

fl_show_simple_input :: (unknown0: *u8, unknown1: *u8) -> *u8 #foreign libforms;

fl_show_colormap :: (unknown0: s32) -> s32 #foreign libforms;

/********* choices *****************/
fl_show_choices :: (unknown0: *u8, unknown1: s32, unknown2: *u8, unknown3: *u8, unknown4: *u8, unknown5: s32) -> s32 #foreign libforms;

fl_show_choice :: (unknown0: *u8, unknown1: *u8, unknown2: *u8, unknown3: s32, unknown4: *u8, unknown5: *u8, unknown6: *u8, unknown7: s32) -> s32 #foreign libforms;

fl_hide_choice :: () -> void #foreign libforms;

fl_set_choices_shortcut :: (unknown0: *u8, unknown1: *u8, unknown2: *u8) -> void #foreign libforms;

/************ one liner ***************/
fl_show_oneliner :: (unknown0: *u8, unknown1: FL_Coord, unknown2: FL_Coord) -> void #foreign libforms;

fl_hide_oneliner :: () -> void #foreign libforms;

fl_set_oneliner_font :: (unknown0: s32, unknown1: s32) -> void #foreign libforms;

fl_set_oneliner_color :: (unknown0: FL_COLOR, unknown1: FL_COLOR) -> void #foreign libforms;

fl_set_tooltip_font :: (unknown0: s32, unknown1: s32) -> void #foreign libforms;

fl_set_tooltip_color :: (unknown0: FL_COLOR, unknown1: FL_COLOR) -> void #foreign libforms;

fl_set_tooltip_boxtype :: (unknown0: s32) -> void #foreign libforms;

fl_set_tooltip_lalign :: (unknown0: s32) -> void #foreign libforms;

/************* command log **************/
FD_CMDLOG :: struct {
    form:          *FL_FORM;
    vdata:         *void; /* UNUSED, remove in later version */
    cdata:         *u8; /* UNUSED, remove in later version */
    ldata:         s64; /* UNUSED, remove in later version */
    browser:       *FL_OBJECT;
    close_browser: *FL_OBJECT;
    clear_browser: *FL_OBJECT;
}

fl_exe_command :: (unknown0: *u8, unknown1: s32) -> s64 #foreign libforms;

fl_end_command :: (unknown0: s64) -> s32 #foreign libforms;

fl_check_command :: (unknown0: s64) -> s32 #foreign libforms;

fl_popen :: (unknown0: *u8, unknown1: *u8) -> *FILE #foreign libforms;

fl_pclose :: (unknown0: *FILE) -> s32 #foreign libforms;

fl_end_all_command :: () -> s32 #foreign libforms;

fl_show_command_log :: (unknown0: s32) -> void #foreign libforms;

fl_hide_command_log :: () -> void #foreign libforms;

fl_clear_command_log :: () -> void #foreign libforms;

fl_addto_command_log :: (unknown0: *u8) -> void #foreign libforms;

fl_addto_command_log_f_CFormat :: (unknown0: *u8, __args: ..Any) -> void #foreign libforms "fl_addto_command_log_f";
fl_addto_command_log_f :: (unknown0: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown0, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_addto_command_log_f_CFormat("%s", formatted_text.data);
} @PrintLike

fl_set_command_log_position :: (unknown0: s32, unknown1: s32) -> void #foreign libforms;

fl_get_command_log_fdstruct :: () -> *FD_CMDLOG #foreign libforms;

FD_FSELECTOR :: struct {
    fselect:  *FL_FORM;
    vdata:    *void;
    cdata:    *void;
    ldata:    s64;
    browser:  *FL_OBJECT;
    input:    *FL_OBJECT;
    prompt:   *FL_OBJECT;
    resbutt:  *FL_OBJECT;
    patbutt:  *FL_OBJECT;
    dirbutt:  *FL_OBJECT;
    cancel:   *FL_OBJECT;
    ready:    *FL_OBJECT;
    dirlabel: *FL_OBJECT;
    patlabel: *FL_OBJECT;
    appbutt:  [3] *FL_OBJECT;
}

fl_use_fselector :: (unknown0: s32) -> s32 #foreign libforms;

fl_show_fselector :: (unknown0: *u8, unknown1: *u8, unknown2: *u8, unknown3: *u8) -> *u8 #foreign libforms;

fl_hide_fselector :: () -> void #foreign libforms;

fl_set_fselector_fontsize :: (unknown0: s32) -> void #foreign libforms;

fl_set_fselector_fontstyle :: (unknown0: s32) -> void #foreign libforms;

fl_set_fselector_placement :: (unknown0: s32) -> void #foreign libforms;

fl_set_fselector_border :: (unknown0: s32) -> void #foreign libforms;

fl_set_fselector_callback :: (unknown0: FL_FSCB, unknown1: *void) -> void #foreign libforms;

fl_get_filename :: () -> *u8 #foreign libforms;

fl_get_directory :: () -> *u8 #foreign libforms;

fl_get_pattern :: () -> *u8 #foreign libforms;

fl_set_directory :: (unknown0: *u8) -> s32 #foreign libforms;

fl_set_pattern :: (unknown0: *u8) -> void #foreign libforms;

fl_refresh_fselector :: () -> void #foreign libforms;

fl_add_fselector_appbutton :: (unknown0: *u8, unknown1: #type (unknown0: *void) -> void #c_call, unknown2: *void) -> void #foreign libforms;

fl_remove_fselector_appbutton :: (unknown0: *u8) -> void #foreign libforms;

fl_disable_fselector_cache :: (unknown0: s32) -> void #foreign libforms;

fl_invalidate_fselector_cache :: () -> void #foreign libforms;

fl_get_fselector_form :: () -> *FL_FORM #foreign libforms;

fl_get_fselector_fdstruct :: () -> *FD_FSELECTOR #foreign libforms;

fl_set_fselector_filetype_marker :: (unknown0: s32, unknown1: s32, unknown2: s32, unknown3: s32, unknown4: s32) -> void #foreign libforms;

fl_goodies_atclose :: (unknown0: *FL_FORM, unknown1: *void) -> s32 #foreign libforms;

fl_show_color_chooser :: (rgb_in: *s32, rgb_out: *s32) -> s32 #foreign libforms;

/***** Types    *****/
FL_INPUT_TYPE :: enum u32 {
    NORMAL_INPUT    :: 0;
    FLOAT_INPUT     :: 1;
    INT_INPUT       :: 2;
    DATE_INPUT      :: 3;
    MULTILINE_INPUT :: 4;
    HIDDEN_INPUT    :: 5;
    SECRET_INPUT    :: 6;

    FL_NORMAL_INPUT    :: NORMAL_INPUT;
    FL_FLOAT_INPUT     :: FLOAT_INPUT;
    FL_INT_INPUT       :: INT_INPUT;
    FL_DATE_INPUT      :: DATE_INPUT;
    FL_MULTILINE_INPUT :: MULTILINE_INPUT;
    FL_HIDDEN_INPUT    :: HIDDEN_INPUT;
    FL_SECRET_INPUT    :: SECRET_INPUT;
}

/* for date input */
FL_INPUT :: enum u32 {
    MMDD :: 0;
    DDMM :: 1;

    FL_INPUT_MMDD :: MMDD;
    FL_INPUT_DDMM :: DDMM;
}

FL_15 :: enum u32 {
    NORMAL_INPUT_MODE :: 0;
    DOS_INPUT_MODE    :: 1;

    FL_NORMAL_INPUT_MODE :: NORMAL_INPUT_MODE;
    FL_DOS_INPUT_MODE    :: DOS_INPUT_MODE;
}

/***** Routines *****/
fl_create_input :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_input :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_input :: (ob: *FL_OBJECT, str: *u8) -> void #foreign libforms;

fl_set_input_f_CFormat :: (obj: *FL_OBJECT, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_set_input_f";
fl_set_input_f :: (obj: *FL_OBJECT, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_set_input_f_CFormat(obj, "%s", formatted_text.data);
} @PrintLike

fl_set_input_return :: (ob: *FL_OBJECT, when: u32) -> void #foreign libforms;

fl_set_input_color :: (ob: *FL_OBJECT, textcol: FL_COLOR, curscol: FL_COLOR) -> void #foreign libforms;

fl_get_input_color :: (ob: *FL_OBJECT, textcol: *FL_COLOR, curscol: *FL_COLOR) -> void #foreign libforms;

fl_set_input_scroll :: (ob: *FL_OBJECT, yes: s32) -> void #foreign libforms;

fl_set_input_cursorpos :: (ob: *FL_OBJECT, xpos: s32, ypos: s32) -> void #foreign libforms;

fl_set_input_selected :: (ob: *FL_OBJECT, yes: s32) -> void #foreign libforms;

fl_set_input_selected_range :: (ob: *FL_OBJECT, begin: s32, end: s32) -> void #foreign libforms;

fl_get_input_selected_range :: (ob: *FL_OBJECT, begin: *s32, end: *s32) -> *u8 #foreign libforms;

fl_set_input_maxchars :: (ob: *FL_OBJECT, maxchars: s32) -> void #foreign libforms;

fl_set_input_format :: (ob: *FL_OBJECT, fmt: s32, sep: s32) -> void #foreign libforms;

fl_set_input_hscrollbar :: (ob: *FL_OBJECT, pref: s32) -> void #foreign libforms;

fl_set_input_vscrollbar :: (ob: *FL_OBJECT, pref: s32) -> void #foreign libforms;

fl_set_input_topline :: (ob: *FL_OBJECT, top: s32) -> void #foreign libforms;

fl_set_input_scrollbarsize :: (ob: *FL_OBJECT, hh: s32, vw: s32) -> void #foreign libforms;

fl_get_input_scrollbarsize :: (ob: *FL_OBJECT, hh: *s32, vw: *s32) -> void #foreign libforms;

fl_set_input_xoffset :: (ob: *FL_OBJECT, xoff: s32) -> void #foreign libforms;

fl_get_input_xoffset :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_input_fieldchar :: (ob: *FL_OBJECT, fchar: s32) -> s32 #foreign libforms;

fl_get_input_topline :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_input_screenlines :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_input_cursorpos :: (ob: *FL_OBJECT, x: *s32, y: *s32) -> s32 #foreign libforms;

fl_set_input_cursor_visible :: (ob: *FL_OBJECT, visible: s32) -> void #foreign libforms;

fl_get_input_numberoflines :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_input_format :: (ob: *FL_OBJECT, fmt: *s32, sep: *s32) -> void #foreign libforms;

fl_get_input :: (ob: *FL_OBJECT) -> *u8 #foreign libforms;

FL_INPUT_VALIDATOR :: #type (unknown0: *FL_OBJECT, unknown1: *u8, unknown2: *u8, unknown3: s32) -> s32 #c_call;

fl_set_input_filter :: (ob: *FL_OBJECT, validate: FL_INPUT_VALIDATOR) -> FL_INPUT_VALIDATOR #foreign libforms;

fl_validate_input :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

/* edit keys. */
FL_EditKeymap :: struct {
    del_prev_char:    s64; /* delete previous char    */
    del_next_char:    s64; /* delete next char        */
    del_prev_word:    s64; /* delete previous word    */
    del_next_word:    s64; /* delete next word        */

    moveto_prev_line: s64; /* one line  up             */
    moveto_next_line: s64; /* one line down            */
    moveto_prev_char: s64; /* one char left            */
    moveto_next_char: s64; /* one char right           */
    moveto_prev_word: s64; /* one word left            */
    moveto_next_word: s64; /* one word right           */
    moveto_prev_page: s64; /* one page up              */
    moveto_next_page: s64; /* one page down            */
    moveto_bol:       s64; /* move to begining of line */
    moveto_eol:       s64; /* move to end of line      */
    moveto_bof:       s64; /* move to begin of file    */
    moveto_eof:       s64; /* move to end of file      */

    transpose:        s64; /* switch two char positions */
    paste:            s64; /* paste the edit buffer    */
    backspace:        s64; /* another  del_prev_char   */
    del_to_bol:       s64; /* cut to begining of line  */
    del_to_eol:       s64; /* cut to end of line       */
    clear_field:      s64; /* delete everything        */
    del_to_eos:       s64; /* not implemented          */
}

fl_set_input_editkeymap :: (keymap: *FL_EditKeymap) -> void #foreign libforms;

fl_get_input_editkeymap :: (keymap: *FL_EditKeymap) -> void #foreign libforms;

fl_set_default_editkeymap :: () -> void #foreign libforms;

fl_set_input_mode :: (mode: s32) -> s32 #foreign libforms;

/************   Object Class: Menu         ************/
FL_MENU_TYPE :: enum u32 {
    TOUCH_MENU    :: 0;
    PUSH_MENU     :: 1;
    PULLDOWN_MENU :: 2;

    FL_TOUCH_MENU    :: TOUCH_MENU;
    FL_PUSH_MENU     :: PUSH_MENU;
    FL_PULLDOWN_MENU :: PULLDOWN_MENU;
}

/***** Routines *****/
fl_create_menu :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_menu :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_clear_menu :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_set_menu_CFormat :: (ob: *FL_OBJECT, menustr: *u8, __args: ..Any) -> void #foreign libforms "fl_set_menu";
fl_set_menu :: (ob: *FL_OBJECT, menustr: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, menustr, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_set_menu_CFormat(ob, "%s", formatted_text.data);
} @PrintLike

fl_addto_menu_CFormat :: (ob: *FL_OBJECT, menustr: *u8, __args: ..Any) -> s32 #foreign libforms "fl_addto_menu";
fl_addto_menu :: (ob: *FL_OBJECT, menustr: string, __args: ..Any) -> s32 {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, menustr, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_addto_menu_CFormat(ob, "%s", formatted_text.data);
} @PrintLike

fl_replace_menu_item_CFormat :: (ob: *FL_OBJECT, numb: s32, str: *u8, __args: ..Any) -> void #foreign libforms "fl_replace_menu_item";
fl_replace_menu_item :: (ob: *FL_OBJECT, numb: s32, str: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, str, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_replace_menu_item_CFormat(ob, numb, "%s", formatted_text.data);
} @PrintLike

fl_delete_menu_item :: (ob: *FL_OBJECT, numb: s32) -> void #foreign libforms;

fl_set_menu_item_callback :: (ob: *FL_OBJECT, numb: s32, cb: FL_PUP_CB) -> FL_PUP_CB #foreign libforms;

fl_set_menu_item_shortcut :: (ob: *FL_OBJECT, numb: s32, str: *u8) -> void #foreign libforms;

fl_set_menu_item_mode :: (ob: *FL_OBJECT, numb: s32, mode: u32) -> void #foreign libforms;

fl_show_menu_symbol :: (ob: *FL_OBJECT, show: s32) -> void #foreign libforms;

fl_set_menu_popup :: (ob: *FL_OBJECT, pup: s32) -> void #foreign libforms;

fl_get_menu_popup :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_menu :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_menu_item_text :: (ob: *FL_OBJECT, numb: s32) -> *u8 #foreign libforms;

fl_get_menu_maxitems :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_menu_item_mode :: (ob: *FL_OBJECT, numb: s32) -> u32 #foreign libforms;

fl_get_menu_text :: (ob: *FL_OBJECT) -> *u8 #foreign libforms;

fl_set_menu_entries :: (ob: *FL_OBJECT, ent: *FL_PUP_ENTRY) -> s32 #foreign libforms;

fl_set_menu_notitle :: (ob: *FL_OBJECT, off: s32) -> s32 #foreign libforms;

fl_set_menu_item_id :: (ob: *FL_OBJECT, item: s32, id: s32) -> s32 #foreign libforms;

/* Nmenu object types */
FL_16 :: enum u32 {
    NORMAL_NMENU       :: 0;
    NORMAL_TOUCH_NMENU :: 1;
    BUTTON_NMENU       :: 2;
    BUTTON_TOUCH_NMENU :: 3;

    FL_NORMAL_NMENU       :: NORMAL_NMENU;
    FL_NORMAL_TOUCH_NMENU :: NORMAL_TOUCH_NMENU;
    FL_BUTTON_NMENU       :: BUTTON_NMENU;
    FL_BUTTON_TOUCH_NMENU :: BUTTON_TOUCH_NMENU;
}

fl_create_nmenu :: (unknown0: s32, unknown1: FL_Coord, unknown2: FL_Coord, unknown3: FL_Coord, unknown4: FL_Coord, unknown5: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_nmenu :: (unknown0: s32, unknown1: FL_Coord, unknown2: FL_Coord, unknown3: FL_Coord, unknown4: FL_Coord, unknown5: *u8) -> *FL_OBJECT #foreign libforms;

fl_clear_nmenu :: (unknown0: *FL_OBJECT) -> s32 #foreign libforms;

fl_add_nmenu_items_CFormat :: (unknown0: *FL_OBJECT, unknown1: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_add_nmenu_items";
fl_add_nmenu_items :: (unknown0: *FL_OBJECT, unknown1: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown1, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_add_nmenu_items_CFormat(unknown0, "%s", formatted_text.data);
} @PrintLike

fl_insert_nmenu_items_CFormat :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY, unknown2: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_insert_nmenu_items";
fl_insert_nmenu_items :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY, unknown2: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown2, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_insert_nmenu_items_CFormat(unknown0, unknown1, "%s", formatted_text.data);
} @PrintLike

fl_replace_nmenu_item_CFormat :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY, unknown2: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_replace_nmenu_item";
fl_replace_nmenu_item :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY, unknown2: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown2, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_replace_nmenu_item_CFormat(unknown0, unknown1, "%s", formatted_text.data);
} @PrintLike

fl_delete_nmenu_item :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY) -> s32 #foreign libforms;

fl_set_nmenu_items :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ITEM) -> *FL_POPUP_ENTRY #foreign libforms;

fl_add_nmenu_items2 :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ITEM) -> *FL_POPUP_ENTRY #foreign libforms;

fl_insert_nmenu_items2 :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY, unknown2: *FL_POPUP_ITEM) -> *FL_POPUP_ENTRY #foreign libforms;

fl_replace_nmenu_items2 :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY, unknown2: *FL_POPUP_ITEM) -> *FL_POPUP_ENTRY #foreign libforms;

fl_get_nmenu_popup :: (unknown0: *FL_OBJECT) -> *FL_POPUP #foreign libforms;

fl_set_nmenu_popup :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP) -> s32 #foreign libforms;

fl_get_nmenu_item :: (unknown0: *FL_OBJECT) -> *FL_POPUP_RETURN #foreign libforms;

fl_get_nmenu_item_by_value :: (unknown0: *FL_OBJECT, unknown1: s64) -> *FL_POPUP_ENTRY #foreign libforms;

fl_get_nmenu_item_by_label :: (unknown0: *FL_OBJECT, unknown1: *u8) -> *FL_POPUP_ENTRY #foreign libforms;

fl_get_nmenu_item_by_text :: (unknown0: *FL_OBJECT, unknown1: *u8) -> *FL_POPUP_ENTRY #foreign libforms;

fl_set_nmenu_policy :: (unknown0: *FL_OBJECT, unknown1: s32) -> s32 #foreign libforms;

fl_set_nmenu_hl_text_color :: (unknown0: *FL_OBJECT, unknown1: FL_COLOR) -> FL_COLOR #foreign libforms;

FL_POSITIONER_VALIDATOR :: #type (obj: *FL_OBJECT, x: float64, y: float64, x_repl: *float64, y_repl: *float64) -> s32 #c_call;

/***** Routines *****/
fl_create_positioner :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_positioner :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_positioner_values :: (obj: *FL_OBJECT, new_x: float64, new_y: float64) -> s32 #foreign libforms;

fl_set_positioner_xvalue :: (ob: *FL_OBJECT, val: float64) -> s32 #foreign libforms;

fl_get_positioner_xvalue :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_positioner_xbounds :: (ob: *FL_OBJECT, min: float64, max: float64) -> void #foreign libforms;

fl_get_positioner_xbounds :: (ob: *FL_OBJECT, min: *float64, max: *float64) -> void #foreign libforms;

fl_set_positioner_yvalue :: (ob: *FL_OBJECT, val: float64) -> s32 #foreign libforms;

fl_get_positioner_yvalue :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_positioner_ybounds :: (ob: *FL_OBJECT, min: float64, max: float64) -> void #foreign libforms;

fl_get_positioner_ybounds :: (ob: *FL_OBJECT, min: *float64, max: *float64) -> void #foreign libforms;

fl_set_positioner_xstep :: (ob: *FL_OBJECT, value: float64) -> void #foreign libforms;

fl_get_positioner_xstep :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_positioner_ystep :: (ob: *FL_OBJECT, value: float64) -> void #foreign libforms;

fl_get_positioner_ystep :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_positioner_return :: (ob: *FL_OBJECT, when: u32) -> void #foreign libforms;

fl_set_positioner_mouse_buttons :: (obj: *FL_OBJECT, mouse_buttons: u32) -> void #foreign libforms;

fl_get_positioner_mouse_buttons :: (obj: *FL_OBJECT, mouse_buttons: *u32) -> void #foreign libforms;

fl_get_positioner_numb :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_positioner_validator :: (obj: *FL_OBJECT, validator: FL_POSITIONER_VALIDATOR) -> FL_POSITIONER_VALIDATOR #foreign libforms;

fl_reset_positioner :: (obj: *FL_OBJECT) -> void #foreign libforms;

FL_17 :: enum u32 {
    VERT_SCROLLBAR       :: 0;
    HOR_SCROLLBAR        :: 1;

    VERT_THIN_SCROLLBAR  :: 2;
    HOR_THIN_SCROLLBAR   :: 3;

    VERT_NICE_SCROLLBAR  :: 4;
    HOR_NICE_SCROLLBAR   :: 5;

    VERT_PLAIN_SCROLLBAR :: 6;
    HOR_PLAIN_SCROLLBAR  :: 7;

    HOR_BASIC_SCROLLBAR  :: 7;
    VERT_BASIC_SCROLLBAR :: 6;

    FL_VERT_SCROLLBAR       :: VERT_SCROLLBAR;
    FL_HOR_SCROLLBAR        :: HOR_SCROLLBAR;

    FL_VERT_THIN_SCROLLBAR  :: VERT_THIN_SCROLLBAR;
    FL_HOR_THIN_SCROLLBAR   :: HOR_THIN_SCROLLBAR;

    FL_VERT_NICE_SCROLLBAR  :: VERT_NICE_SCROLLBAR;
    FL_HOR_NICE_SCROLLBAR   :: HOR_NICE_SCROLLBAR;

    FL_VERT_PLAIN_SCROLLBAR :: VERT_PLAIN_SCROLLBAR;
    FL_HOR_PLAIN_SCROLLBAR  :: HOR_PLAIN_SCROLLBAR;

    FL_HOR_BASIC_SCROLLBAR  :: HOR_BASIC_SCROLLBAR;
    FL_VERT_BASIC_SCROLLBAR :: VERT_BASIC_SCROLLBAR;
}

FL_18 :: enum u32 {
    NORMAL_SCROLLBAR :: 0;
    THIN_SCROLLBAR   :: 1;
    NICE_SCROLLBAR   :: 2;
    PLAIN_SCROLLBAR  :: 3;

    FL_NORMAL_SCROLLBAR :: NORMAL_SCROLLBAR;
    FL_THIN_SCROLLBAR   :: THIN_SCROLLBAR;
    FL_NICE_SCROLLBAR   :: NICE_SCROLLBAR;
    FL_PLAIN_SCROLLBAR  :: PLAIN_SCROLLBAR;
}

fl_create_scrollbar :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_scrollbar :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_get_scrollbar_value :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_scrollbar_value :: (ob: *FL_OBJECT, val: float64) -> void #foreign libforms;

fl_set_scrollbar_size :: (ob: *FL_OBJECT, val: float64) -> void #foreign libforms;

fl_get_scrollbar_size :: (obj: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_scrollbar_increment :: (ob: *FL_OBJECT, l: float64, r: float64) -> void #foreign libforms;

fl_get_scrollbar_increment :: (ob: *FL_OBJECT, a: *float64, b: *float64) -> void #foreign libforms;

fl_set_scrollbar_bounds :: (ob: *FL_OBJECT, b1: float64, b2: float64) -> void #foreign libforms;

fl_get_scrollbar_bounds :: (ob: *FL_OBJECT, b1: *float64, b2: *float64) -> void #foreign libforms;

fl_set_scrollbar_return :: (ob: *FL_OBJECT, when: u32) -> void #foreign libforms;

fl_set_scrollbar_step :: (ob: *FL_OBJECT, step: float64) -> void #foreign libforms;

fl_get_scrollbar_repeat :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_scrollbar_repeat :: (obj: *FL_OBJECT, millisec: s32) -> void #foreign libforms;

/* Select object types */
FL_19 :: enum u32 {
    NORMAL_SELECT   :: 0;
    MENU_SELECT     :: 1;
    DROPLIST_SELECT :: 2;

    FL_NORMAL_SELECT   :: NORMAL_SELECT;
    FL_MENU_SELECT     :: MENU_SELECT;
    FL_DROPLIST_SELECT :: DROPLIST_SELECT;
}

fl_create_select :: (unknown0: s32, unknown1: FL_Coord, unknown2: FL_Coord, unknown3: FL_Coord, unknown4: FL_Coord, unknown5: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_select :: (unknown0: s32, unknown1: FL_Coord, unknown2: FL_Coord, unknown3: FL_Coord, unknown4: FL_Coord, unknown5: *u8) -> *FL_OBJECT #foreign libforms;

fl_clear_select :: (unknown0: *FL_OBJECT) -> s32 #foreign libforms;

fl_add_select_items_CFormat :: (unknown0: *FL_OBJECT, unknown1: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_add_select_items";
fl_add_select_items :: (unknown0: *FL_OBJECT, unknown1: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown1, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_add_select_items_CFormat(unknown0, "%s", formatted_text.data);
} @PrintLike

fl_insert_select_items_CFormat :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY, unknown2: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_insert_select_items";
fl_insert_select_items :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY, unknown2: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown2, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_insert_select_items_CFormat(unknown0, unknown1, "%s", formatted_text.data);
} @PrintLike

fl_replace_select_item_CFormat :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY, unknown2: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_replace_select_item";
fl_replace_select_item :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY, unknown2: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown2, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_replace_select_item_CFormat(unknown0, unknown1, "%s", formatted_text.data);
} @PrintLike

fl_delete_select_item :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY) -> s32 #foreign libforms;

fl_set_select_items :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ITEM) -> s64 #foreign libforms;

fl_get_select_popup :: (unknown0: *FL_OBJECT) -> *FL_POPUP #foreign libforms;

fl_set_select_popup :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP) -> s32 #foreign libforms;

fl_get_select_item :: (unknown0: *FL_OBJECT) -> *FL_POPUP_RETURN #foreign libforms;

fl_set_select_item :: (unknown0: *FL_OBJECT, unknown1: *FL_POPUP_ENTRY) -> *FL_POPUP_RETURN #foreign libforms;

fl_get_select_item_by_value :: (unknown0: *FL_OBJECT, unknown1: s64) -> *FL_POPUP_ENTRY #foreign libforms;

fl_get_select_item_by_label :: (unknown0: *FL_OBJECT, unknown1: *u8) -> *FL_POPUP_ENTRY #foreign libforms;

fl_get_select_item_by_label_f_CFormat :: (unknown0: *FL_OBJECT, unknown1: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_get_select_item_by_label_f";
fl_get_select_item_by_label_f :: (unknown0: *FL_OBJECT, unknown1: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, unknown1, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_get_select_item_by_label_f_CFormat(unknown0, "%s", formatted_text.data);
} @PrintLike

fl_get_select_item_by_text_f_CFormat :: (obj: *FL_OBJECT, fmt: *u8, __args: ..Any) -> *FL_POPUP_ENTRY #foreign libforms "fl_get_select_item_by_text_f";
fl_get_select_item_by_text_f :: (obj: *FL_OBJECT, fmt: string, __args: ..Any) -> *FL_POPUP_ENTRY {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_get_select_item_by_text_f_CFormat(obj, "%s", formatted_text.data);
} @PrintLike

fl_get_select_item_by_text :: (unknown0: *FL_OBJECT, unknown1: *u8) -> *FL_POPUP_ENTRY #foreign libforms;

fl_get_select_text_color :: (unknown0: *FL_OBJECT) -> FL_COLOR #foreign libforms;

fl_set_select_text_color :: (unknown0: *FL_OBJECT, unknown1: FL_COLOR) -> FL_COLOR #foreign libforms;

fl_get_select_text_font :: (unknown0: *FL_OBJECT, unknown1: *s32, unknown2: *s32) -> s32 #foreign libforms;

fl_set_select_text_font :: (unknown0: *FL_OBJECT, unknown1: s32, unknown2: s32) -> s32 #foreign libforms;

fl_get_select_text_align :: (unknown0: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_select_text_align :: (unknown0: *FL_OBJECT, unknown1: s32) -> s32 #foreign libforms;

fl_set_select_policy :: (unknown0: *FL_OBJECT, unknown1: s32) -> s32 #foreign libforms;

FL_SLIDER_TYPE :: enum u32 {
    VERT_SLIDER          :: 0;
    HOR_SLIDER           :: 1;

    VERT_FILL_SLIDER     :: 2;
    HOR_FILL_SLIDER      :: 3;

    VERT_NICE_SLIDER     :: 4;
    HOR_NICE_SLIDER      :: 5;

    VERT_BROWSER_SLIDER  :: 6;
    HOR_BROWSER_SLIDER   :: 7;

    VERT_PROGRESS_BAR    :: 8;
    HOR_PROGRESS_BAR     :: 9;

    VERT_BROWSER_SLIDER2 :: 16;
    HOR_BROWSER_SLIDER2  :: 17;

    VERT_THIN_SLIDER     :: 18;
    HOR_THIN_SLIDER      :: 19;

    VERT_NICE_SLIDER2    :: 20;
    HOR_NICE_SLIDER2     :: 21;

    VERT_BASIC_SLIDER    :: 22;
    HOR_BASIC_SLIDER     :: 23;

    FL_VERT_SLIDER          :: VERT_SLIDER;
    FL_HOR_SLIDER           :: HOR_SLIDER;

    FL_VERT_FILL_SLIDER     :: VERT_FILL_SLIDER;
    FL_HOR_FILL_SLIDER      :: HOR_FILL_SLIDER;

    FL_VERT_NICE_SLIDER     :: VERT_NICE_SLIDER;
    FL_HOR_NICE_SLIDER      :: HOR_NICE_SLIDER;

    FL_VERT_BROWSER_SLIDER  :: VERT_BROWSER_SLIDER;
    FL_HOR_BROWSER_SLIDER   :: HOR_BROWSER_SLIDER;

    FL_VERT_PROGRESS_BAR    :: VERT_PROGRESS_BAR;
    FL_HOR_PROGRESS_BAR     :: HOR_PROGRESS_BAR;

    FL_VERT_BROWSER_SLIDER2 :: VERT_BROWSER_SLIDER2;
    FL_HOR_BROWSER_SLIDER2  :: HOR_BROWSER_SLIDER2;

    FL_VERT_THIN_SLIDER     :: VERT_THIN_SLIDER;
    FL_HOR_THIN_SLIDER      :: HOR_THIN_SLIDER;

    FL_VERT_NICE_SLIDER2    :: VERT_NICE_SLIDER2;
    FL_HOR_NICE_SLIDER2     :: HOR_NICE_SLIDER2;

    FL_VERT_BASIC_SLIDER    :: VERT_BASIC_SLIDER;
    FL_HOR_BASIC_SLIDER     :: HOR_BASIC_SLIDER;
}

/***** Routines *****/
fl_create_slider :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_slider :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_create_valslider :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_valslider :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_slider_value :: (ob: *FL_OBJECT, val: float64) -> void #foreign libforms;

fl_get_slider_value :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_slider_bounds :: (ob: *FL_OBJECT, min: float64, max: float64) -> void #foreign libforms;

fl_get_slider_bounds :: (ob: *FL_OBJECT, min: *float64, max: *float64) -> void #foreign libforms;

fl_set_slider_return :: (ob: *FL_OBJECT, value: u32) -> void #foreign libforms;

fl_set_slider_step :: (ob: *FL_OBJECT, value: float64) -> void #foreign libforms;

fl_set_slider_increment :: (ob: *FL_OBJECT, l: float64, r: float64) -> void #foreign libforms;

fl_get_slider_increment :: (ob: *FL_OBJECT, l: *float64, r: *float64) -> void #foreign libforms;

fl_set_slider_size :: (ob: *FL_OBJECT, size: float64) -> void #foreign libforms;

fl_get_slider_size :: (obj: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_slider_precision :: (ob: *FL_OBJECT, prec: s32) -> void #foreign libforms;

fl_set_slider_filter :: (ob: *FL_OBJECT, filter: FL_VAL_FILTER) -> void #foreign libforms;

fl_get_slider_repeat :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_set_slider_repeat :: (obj: *FL_OBJECT, millisec: s32) -> void #foreign libforms;

fl_set_slider_mouse_buttons :: (obj: *FL_OBJECT, mouse_buttons: u32) -> void #foreign libforms;

fl_get_slider_mouse_buttons :: (obj: *FL_OBJECT, mouse_buttons: *u32) -> void #foreign libforms;

FL_SPINNER_TYPE :: enum u32 {
    INT_SPINNER   :: 0;
    FLOAT_SPINNER :: 1;

    FL_INT_SPINNER   :: INT_SPINNER;
    FL_FLOAT_SPINNER :: FLOAT_SPINNER;
}

fl_create_spinner :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_spinner :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_get_spinner_value :: (obj: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_spinner_value :: (obj: *FL_OBJECT, val: float64) -> float64 #foreign libforms;

fl_set_spinner_bounds :: (obj: *FL_OBJECT, min: float64, max: float64) -> void #foreign libforms;

fl_get_spinner_bounds :: (obj: *FL_OBJECT, min: *float64, max: *float64) -> void #foreign libforms;

fl_set_spinner_step :: (obj: *FL_OBJECT, step: float64) -> void #foreign libforms;

fl_get_spinner_step :: (obj: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_spinner_precision :: (obj: *FL_OBJECT, prec: s32) -> void #foreign libforms;

fl_get_spinner_precision :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_spinner_input :: (obj: *FL_OBJECT) -> *FL_OBJECT #foreign libforms;

fl_get_spinner_up_button :: (obj: *FL_OBJECT) -> *FL_OBJECT #foreign libforms;

fl_get_spinner_down_button :: (obj: *FL_OBJECT) -> *FL_OBJECT #foreign libforms;

FL_20 :: enum u32 {
    TOP_TABFOLDER    :: 0;
    BOTTOM_TABFOLDER :: 1;
    LEFT_TABFOLDER   :: 2;
    RIGHT_TABFOLDER  :: 3;
    NORMAL_TABFOLDER :: 0;

    FL_TOP_TABFOLDER    :: TOP_TABFOLDER;
    FL_BOTTOM_TABFOLDER :: BOTTOM_TABFOLDER;
    FL_LEFT_TABFOLDER   :: LEFT_TABFOLDER;
    FL_RIGHT_TABFOLDER  :: RIGHT_TABFOLDER;
    FL_NORMAL_TABFOLDER :: NORMAL_TABFOLDER;
}

FL_21 :: enum u32 {
    NO           :: 0;
    FIT          :: 1;
    ENLARGE_ONLY :: 2;

    FL_NO           :: NO;
    FL_FIT          :: FIT;
    FL_ENLARGE_ONLY :: ENLARGE_ONLY;
}

fl_create_tabfolder :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_tabfolder :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_addto_tabfolder :: (ob: *FL_OBJECT, title: *u8, form: *FL_FORM) -> *FL_OBJECT #foreign libforms;

fl_get_tabfolder_folder_bynumber :: (ob: *FL_OBJECT, num: s32) -> *FL_FORM #foreign libforms;

fl_get_tabfolder_folder_byname :: (ob: *FL_OBJECT, name: *u8) -> *FL_FORM #foreign libforms;

fl_get_tabfolder_folder_byname_f_CFormat :: (ob: *FL_OBJECT, fmt: *u8, __args: ..Any) -> *FL_FORM #foreign libforms "fl_get_tabfolder_folder_byname_f";
fl_get_tabfolder_folder_byname_f :: (ob: *FL_OBJECT, fmt: string, __args: ..Any) -> *FL_FORM {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_get_tabfolder_folder_byname_f_CFormat(ob, "%s", formatted_text.data);
} @PrintLike

fl_delete_folder :: (ob: *FL_OBJECT, form: *FL_FORM) -> void #foreign libforms;

fl_delete_folder_bynumber :: (ob: *FL_OBJECT, num: s32) -> void #foreign libforms;

fl_delete_folder_byname :: (ob: *FL_OBJECT, name: *u8) -> void #foreign libforms;

fl_delete_folder_byname_f_CFormat :: (ob: *FL_OBJECT, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_delete_folder_byname_f";
fl_delete_folder_byname_f :: (ob: *FL_OBJECT, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_delete_folder_byname_f_CFormat(ob, "%s", formatted_text.data);
} @PrintLike

fl_set_folder :: (ob: *FL_OBJECT, form: *FL_FORM) -> void #foreign libforms;

fl_set_folder_byname :: (ob: *FL_OBJECT, name: *u8) -> void #foreign libforms;

fl_set_folder_byname_f_CFormat :: (ob: *FL_OBJECT, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_set_folder_byname_f";
fl_set_folder_byname_f :: (ob: *FL_OBJECT, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_set_folder_byname_f_CFormat(ob, "%s", formatted_text.data);
} @PrintLike

fl_set_folder_bynumber :: (ob: *FL_OBJECT, num: s32) -> void #foreign libforms;

fl_get_folder :: (ob: *FL_OBJECT) -> *FL_FORM #foreign libforms;

fl_get_folder_number :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_folder_name :: (ob: *FL_OBJECT) -> *u8 #foreign libforms;

fl_get_tabfolder_numfolders :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_active_folder :: (ob: *FL_OBJECT) -> *FL_FORM #foreign libforms;

fl_get_active_folder_number :: (ob: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_active_folder_name :: (ob: *FL_OBJECT) -> *u8 #foreign libforms;

fl_get_folder_area :: (ob: *FL_OBJECT, x: *FL_Coord, y: *FL_Coord, w: *FL_Coord, h: *FL_Coord) -> void #foreign libforms;

fl_replace_folder_bynumber :: (ob: *FL_OBJECT, num: s32, form: *FL_FORM) -> void #foreign libforms;

fl_set_tabfolder_autofit :: (ob: *FL_OBJECT, y: s32) -> s32 #foreign libforms;

fl_set_default_tabfolder_corner :: (n: s32) -> s32 #foreign libforms;

fl_set_tabfolder_offset :: (obj: *FL_OBJECT, offset: s32) -> s32 #foreign libforms;

fl_get_tabfolder_offset :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

anon_enum_1 :: enum u32 {
    FL_NORMAL_TEXT :: 0;
}

fl_create_text :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_text :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

FL_22 :: enum u32 {
    VERT_THUMBWHEEL :: 0;
    HOR_THUMBWHEEL  :: 1;

    FL_VERT_THUMBWHEEL :: VERT_THUMBWHEEL;
    FL_HOR_THUMBWHEEL  :: HOR_THUMBWHEEL;
}

fl_get_thumbwheel_value :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_thumbwheel_value :: (ob: *FL_OBJECT, value: float64) -> float64 #foreign libforms;

fl_get_thumbwheel_step :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_thumbwheel_step :: (ob: *FL_OBJECT, step: float64) -> float64 #foreign libforms;

fl_set_thumbwheel_return :: (ob: *FL_OBJECT, when: u32) -> s32 #foreign libforms;

fl_set_thumbwheel_crossover :: (ob: *FL_OBJECT, flag: s32) -> s32 #foreign libforms;

fl_set_thumbwheel_bounds :: (ob: *FL_OBJECT, min: float64, max: float64) -> void #foreign libforms;

fl_get_thumbwheel_bounds :: (ob: *FL_OBJECT, min: *float64, max: *float64) -> void #foreign libforms;

fl_create_thumbwheel :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_thumbwheel :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

FL_TIMER_TYPE :: enum u32 {
    NORMAL_TIMER :: 0;
    VALUE_TIMER  :: 1;
    HIDDEN_TIMER :: 2;

    FL_NORMAL_TIMER :: NORMAL_TIMER;
    FL_VALUE_TIMER  :: VALUE_TIMER;
    FL_HIDDEN_TIMER :: HIDDEN_TIMER;
}

/***** Routines *****/
FL_TIMER_FILTER :: #type (unknown0: *FL_OBJECT, unknown1: float64) -> *u8 #c_call;

fl_create_timer :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_timer :: (type: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_timer :: (ob: *FL_OBJECT, total: float64) -> void #foreign libforms;

fl_get_timer :: (ob: *FL_OBJECT) -> float64 #foreign libforms;

fl_set_timer_countup :: (ob: *FL_OBJECT, yes: s32) -> void #foreign libforms;

fl_set_timer_filter :: (ob: *FL_OBJECT, filter: FL_TIMER_FILTER) -> FL_TIMER_FILTER #foreign libforms;

fl_suspend_timer :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_resume_timer :: (ob: *FL_OBJECT) -> void #foreign libforms;

FL_PUP_ENTERCB :: #type (unknown0: s32, unknown1: *void) -> void #c_call;
FL_PUP_LEAVECB :: #type (unknown0: s32, unknown1: *void) -> void #c_call;

fl_setpup_entries :: (nm: s32, entries: *FL_PUP_ENTRY) -> s32 #foreign libforms;

fl_newpup :: (win: Window) -> s32 #foreign libforms;

fl_defpup_CFormat :: (win: Window, str: *u8, __args: ..Any) -> s32 #foreign libforms "fl_defpup";
fl_defpup :: (win: Window, str: string, __args: ..Any) -> s32 {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, str, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_defpup_CFormat(win, "%s", formatted_text.data);
} @PrintLike

fl_addtopup_CFormat :: (n: s32, str: *u8, __args: ..Any) -> s32 #foreign libforms "fl_addtopup";
fl_addtopup :: (n: s32, str: string, __args: ..Any) -> s32 {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, str, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    return fl_addtopup_CFormat(n, "%s", formatted_text.data);
} @PrintLike

fl_setpup_mode :: (nm: s32, ni: s32, mode: u32) -> s32 #foreign libforms;

fl_freepup :: (n: s32) -> void #foreign libforms;

fl_dopup :: (n: s32) -> s32 #foreign libforms;

fl_setpup_default_cursor :: (cursor: s32) -> Cursor #foreign libforms;

fl_setpup_default_color :: (fg: FL_COLOR, bg: FL_COLOR) -> void #foreign libforms;

fl_setpup_default_pup_checked_color :: (col: FL_COLOR) -> void #foreign libforms;

fl_setpup_default_fontsize :: (size: s32) -> s32 #foreign libforms;

fl_setpup_default_fontstyle :: (style: s32) -> s32 #foreign libforms;

fl_setpup_default_bw :: (bw: s32) -> s32 #foreign libforms;

fl_setpup_shortcut :: (nm: s32, ni: s32, sc: *u8) -> void #foreign libforms;

fl_setpup_position :: (x: s32, y: s32) -> void #foreign libforms;

fl_setpup_align_bottom :: () -> void #foreign libforms;

fl_setpup_selection :: (nm: s32, ni: s32) -> void #foreign libforms;

fl_setpup_shadow :: (n: s32, y: s32) -> void #foreign libforms;

fl_setpup_softedge :: (n: s32, y: s32) -> void #foreign libforms;

fl_setpup_bw :: (n: s32, bw: s32) -> void #foreign libforms;

fl_setpup_title :: (nm: s32, title: *u8) -> void #foreign libforms;

fl_setpup_title_f_CFormat :: (nm: s32, fmt: *u8, __args: ..Any) -> void #foreign libforms "fl_setpup_title_f";
fl_setpup_title_f :: (nm: s32, fmt: string, __args: ..Any) {
    push_allocator(temp);
    formatted_text_builder: String_Builder;
    print_to_builder(*formatted_text_builder, fmt, ..__args);
    append(*formatted_text_builder, "\0");
    formatted_text := builder_to_string(*formatted_text_builder);
    fl_setpup_title_f_CFormat(nm, "%s", formatted_text.data);
} @PrintLike

fl_setpup_entercb :: (nm: s32, cb: FL_PUP_ENTERCB, data: *void) -> FL_PUP_ENTERCB #foreign libforms;

fl_setpup_leavecb :: (nm: s32, cb: FL_PUP_LEAVECB, data: *void) -> FL_PUP_LEAVECB #foreign libforms;

fl_setpup_pad :: (n: s32, padw: s32, padh: s32) -> void #foreign libforms;

fl_setpup_cursor :: (nm: s32, cursor: s32) -> Cursor #foreign libforms;

fl_setpup_maxpup :: (n: s32) -> s32 #foreign libforms;

fl_getpup_mode :: (nm: s32, ni: s32) -> u32 #foreign libforms;

fl_getpup_text :: (nm: s32, ni: s32) -> *u8 #foreign libforms;

fl_showpup :: (n: s32) -> void #foreign libforms;

fl_hidepup :: (n: s32) -> void #foreign libforms;

fl_getpup_items :: (n: s32) -> s32 #foreign libforms;

fl_current_pup :: () -> s32 #foreign libforms;

fl_setpup_itemcb :: (nm: s32, ni: s32, cb: FL_PUP_CB) -> FL_PUP_CB #foreign libforms;

fl_setpup_menucb :: (nm: s32, cb: FL_PUP_CB) -> FL_PUP_CB #foreign libforms;

fl_setpup_submenu :: (m: s32, i: s32, subm: s32) -> void #foreign libforms;

/*  Class FL_XYPLOT */
FL_XYPLOT_TYPE :: enum u32 {
    NORMAL_XYPLOT     :: 0;
    SQUARE_XYPLOT     :: 1;
    CIRCLE_XYPLOT     :: 2;
    FILL_XYPLOT       :: 3;
    POINTS_XYPLOT     :: 4;
    DASHED_XYPLOT     :: 5;
    IMPULSE_XYPLOT    :: 6;
    ACTIVE_XYPLOT     :: 7;
    EMPTY_XYPLOT      :: 8;
    DOTTED_XYPLOT     :: 9;
    DOTDASHED_XYPLOT  :: 10;
    LONGDASHED_XYPLOT :: 11;
    LINEPOINTS_XYPLOT :: 12;

    FL_NORMAL_XYPLOT     :: NORMAL_XYPLOT;
    FL_SQUARE_XYPLOT     :: SQUARE_XYPLOT;
    FL_CIRCLE_XYPLOT     :: CIRCLE_XYPLOT;
    FL_FILL_XYPLOT       :: FILL_XYPLOT;
    FL_POINTS_XYPLOT     :: POINTS_XYPLOT;
    FL_DASHED_XYPLOT     :: DASHED_XYPLOT;
    FL_IMPULSE_XYPLOT    :: IMPULSE_XYPLOT;
    FL_ACTIVE_XYPLOT     :: ACTIVE_XYPLOT;
    FL_EMPTY_XYPLOT      :: EMPTY_XYPLOT;
    FL_DOTTED_XYPLOT     :: DOTTED_XYPLOT;
    FL_DOTDASHED_XYPLOT  :: DOTDASHED_XYPLOT;
    FL_LONGDASHED_XYPLOT :: LONGDASHED_XYPLOT;
    FL_LINEPOINTS_XYPLOT :: LINEPOINTS_XYPLOT;
}

FL_23 :: enum u32 {
    LINEAR :: 0;
    LOG    :: 1;

    FL_LINEAR :: LINEAR;
    FL_LOG    :: LOG;
}

FL_GRID :: enum u32 {
    NONE  :: 0;
    MAJOR :: 1;
    MINOR :: 2;

    FL_GRID_NONE  :: NONE;
    FL_GRID_MAJOR :: MAJOR;
    FL_GRID_MINOR :: MINOR;
}

/***** Others   *****/
fl_create_xyplot :: (t: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_add_xyplot :: (t: s32, x: FL_Coord, y: FL_Coord, w: FL_Coord, h: FL_Coord, label: *u8) -> *FL_OBJECT #foreign libforms;

fl_set_xyplot_data :: (ob: *FL_OBJECT, x: *float, y: *float, n: s32, title: *u8, xlabel: *u8, ylabel: *u8) -> void #foreign libforms;

fl_set_xyplot_data_double :: (ob: *FL_OBJECT, x: *float64, y: *float64, n: s32, title: *u8, xlabel: *u8, ylabel: *u8) -> void #foreign libforms;

fl_set_xyplot_file :: (ob: *FL_OBJECT, f: *u8, title: *u8, xl: *u8, yl: *u8) -> s32 #foreign libforms;

fl_insert_xyplot_data :: (ob: *FL_OBJECT, id: s32, n: s32, x: float64, y: float64) -> void #foreign libforms;

fl_add_xyplot_text :: (ob: *FL_OBJECT, x: float64, y: float64, text: *u8, al: s32, col: FL_COLOR) -> void #foreign libforms;

fl_delete_xyplot_text :: (ob: *FL_OBJECT, text: *u8) -> void #foreign libforms;

fl_set_xyplot_maxoverlays :: (ob: *FL_OBJECT, maxover: s32) -> s32 #foreign libforms;

fl_add_xyplot_overlay :: (ob: *FL_OBJECT, id: s32, x: *float, y: *float, n: s32, col: FL_COLOR) -> void #foreign libforms;

fl_add_xyplot_overlay_file :: (ob: *FL_OBJECT, id: s32, f: *u8, c: FL_COLOR) -> s32 #foreign libforms;

fl_set_xyplot_return :: (ob: *FL_OBJECT, when: u32) -> void #foreign libforms;

fl_set_xyplot_xtics :: (ob: *FL_OBJECT, major: s32, minor: s32) -> void #foreign libforms;

fl_set_xyplot_ytics :: (ob: *FL_OBJECT, major: s32, minor: s32) -> void #foreign libforms;

fl_set_xyplot_xbounds :: (ob: *FL_OBJECT, xmin: float64, xmax: float64) -> void #foreign libforms;

fl_set_xyplot_ybounds :: (ob: *FL_OBJECT, ymin: float64, ymax: float64) -> void #foreign libforms;

fl_get_xyplot_xbounds :: (ob: *FL_OBJECT, xmin: *float, xmax: *float) -> void #foreign libforms;

fl_get_xyplot_ybounds :: (ob: *FL_OBJECT, ymin: *float, ymax: *float) -> void #foreign libforms;

fl_get_xyplot :: (ob: *FL_OBJECT, x: *float, y: *float, i: *s32) -> void #foreign libforms;

fl_get_xyplot_data_size :: (obj: *FL_OBJECT) -> s32 #foreign libforms;

fl_get_xyplot_data :: (ob: *FL_OBJECT, x: *float, y: *float, n: *s32) -> void #foreign libforms;

fl_get_xyplot_data_pointer :: (ob: *FL_OBJECT, id: s32, x: **float, y: **float, n: *s32) -> void #foreign libforms;

fl_get_xyplot_overlay_data :: (ob: *FL_OBJECT, id: s32, x: *float, y: *float, n: *s32) -> void #foreign libforms;

fl_set_xyplot_overlay_type :: (ob: *FL_OBJECT, id: s32, type: s32) -> void #foreign libforms;

fl_delete_xyplot_overlay :: (ob: *FL_OBJECT, id: s32) -> void #foreign libforms;

fl_set_xyplot_interpolate :: (ob: *FL_OBJECT, id: s32, deg: s32, grid: float64) -> void #foreign libforms;

fl_set_xyplot_inspect :: (ob: *FL_OBJECT, yes: s32) -> void #foreign libforms;

fl_set_xyplot_symbolsize :: (ob: *FL_OBJECT, n: s32) -> void #foreign libforms;

fl_replace_xyplot_point :: (ob: *FL_OBJECT, i: s32, x: float64, y: float64) -> void #foreign libforms;

/* Replace the value of a particular point in dataset setID,
* where setID=0 is the first data set.
* This routine is an extension of fl_replace_xyplot_point
* which acts on the first dataset only. */
fl_replace_xyplot_point_in_overlay :: (ob: *FL_OBJECT, i: s32, setID: s32, x: float64, y: float64) -> void #foreign libforms;

fl_get_xyplot_xmapping :: (ob: *FL_OBJECT, a: *float, b: *float) -> void #foreign libforms;

fl_get_xyplot_ymapping :: (ob: *FL_OBJECT, a: *float, b: *float) -> void #foreign libforms;

fl_set_xyplot_keys :: (ob: *FL_OBJECT, keys: **u8, x: float, y: float, align: s32) -> void #foreign libforms;

fl_set_xyplot_key :: (ob: *FL_OBJECT, id: s32, key: *u8) -> void #foreign libforms;

fl_set_xyplot_key_position :: (ob: *FL_OBJECT, x: float, y: float, align: s32) -> void #foreign libforms;

fl_set_xyplot_key_font :: (ob: *FL_OBJECT, style: s32, size: s32) -> void #foreign libforms;

fl_get_xyplot_numdata :: (ob: *FL_OBJECT, id: s32) -> s32 #foreign libforms;

/* The following two functions will be removed.
* Use fl_set_object_l[size|style] for the functionalities */
fl_set_xyplot_fontsize :: (ob: *FL_OBJECT, size: s32) -> void #foreign libforms;

fl_set_xyplot_fontstyle :: (ob: *FL_OBJECT, style: s32) -> void #foreign libforms;

fl_xyplot_s2w :: (ob: *FL_OBJECT, sx: float64, sy: float64, wx: *float, wy: *float) -> void #foreign libforms;

fl_xyplot_w2s :: (ob: *FL_OBJECT, wx: float64, wy: float64, sx: *float, sy: *float) -> void #foreign libforms;

fl_set_xyplot_xscale :: (ob: *FL_OBJECT, scale: s32, base: float64) -> void #foreign libforms;

fl_set_xyplot_yscale :: (ob: *FL_OBJECT, scale: s32, base: float64) -> void #foreign libforms;

fl_clear_xyplot :: (ob: *FL_OBJECT) -> void #foreign libforms;

fl_set_xyplot_linewidth :: (ob: *FL_OBJECT, id: s32, lw: s32) -> void #foreign libforms;

fl_set_xyplot_xgrid :: (ob: *FL_OBJECT, xgrid: s32) -> void #foreign libforms;

fl_set_xyplot_ygrid :: (ob: *FL_OBJECT, ygrid: s32) -> void #foreign libforms;

fl_set_xyplot_grid_linestyle :: (ob: *FL_OBJECT, style: s32) -> s32 #foreign libforms;

fl_set_xyplot_alphaxtics :: (ob: *FL_OBJECT, m: *u8, s: *u8) -> void #foreign libforms;

fl_set_xyplot_alphaytics :: (ob: *FL_OBJECT, m: *u8, s: *u8) -> void #foreign libforms;

fl_set_xyplot_fixed_xaxis :: (ob: *FL_OBJECT, lm: *u8, rm: *u8) -> void #foreign libforms;

fl_set_xyplot_fixed_yaxis :: (ob: *FL_OBJECT, bm: *u8, tm: *u8) -> void #foreign libforms;

fl_interpolate :: (wx: *float, wy: *float, nin: s32, x: *float, y: *float, grid: float64, ndeg: s32) -> s32 #foreign libforms;

FL_XYPLOT_SYMBOL :: #type (unknown0: *FL_OBJECT, unknown1: s32, unknown2: *FL_POINT, unknown3: s32, unknown4: s32, unknown5: s32) -> void #c_call;

fl_set_xyplot_symbol :: (ob: *FL_OBJECT, id: s32, symbol: FL_XYPLOT_SYMBOL) -> FL_XYPLOT_SYMBOL #foreign libforms;

fl_set_xyplot_mark_active :: (ob: *FL_OBJECT, y: s32) -> s32 #foreign libforms;

fl_get_xyplot_screen_area :: (obj: *FL_OBJECT, llx: *FL_Coord, lly: *FL_Coord, urx: *FL_Coord, ury: *FL_Coord) -> void #foreign libforms;

fl_get_xyplot_world_area :: (obj: *FL_OBJECT, llx: *float, lly: *float, urx: *float, ury: *float) -> void #foreign libforms;

fl_set_xyplot_log_minor_xtics :: (obj: *FL_OBJECT, yesno: s32) -> s32 #foreign libforms;

fl_set_xyplot_log_minor_ytics :: (obj: *FL_OBJECT, yesno: s32) -> s32 #foreign libforms;

fl_set_xyplot_mouse_buttons :: (obj: *FL_OBJECT, mouse_buttons: u32) -> void #foreign libforms;

fl_get_xyplot_mouse_buttons :: (obj: *FL_OBJECT, mouse_buttons: *u32) -> void #foreign libforms;

fl_gc_ :: () -> GC #foreign libforms;
fl_textgc_ :: () -> GC #foreign libforms;
fl_fheight_ :: () -> s32 #foreign libforms;
fl_fdesc_ :: () -> s32 #foreign libforms;
fl_cur_win_ :: () -> Window #foreign libforms;
fl_cur_fs_ :: () -> *XFontStruct #foreign libforms;
fl_display_ :: () -> *Display #foreign libforms;

#scope_file

#import "Basic"; // For assert, push_context

libforms :: #library,no_dll ".//libforms";

#run {
    {
        info := type_info(FL_PUP_ENTRY);
        for info.members {
            if it.name == {
                case "text";
                    assert(it.offset_in_bytes == 0, "FL_PUP_ENTRY.text has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_PUP_ENTRY.text has unexpected size % instead of 8", it.type.runtime_size);
                case "callback";
                    assert(it.offset_in_bytes == 8, "FL_PUP_ENTRY.callback has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_PUP_ENTRY.callback has unexpected size % instead of 8", it.type.runtime_size);
                case "shortcut";
                    assert(it.offset_in_bytes == 16, "FL_PUP_ENTRY.shortcut has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_PUP_ENTRY.shortcut has unexpected size % instead of 8", it.type.runtime_size);
                case "mode";
                    assert(it.offset_in_bytes == 24, "FL_PUP_ENTRY.mode has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_PUP_ENTRY.mode has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(FL_PUP_ENTRY) == 32, "FL_PUP_ENTRY has size % instead of 32", size_of(FL_PUP_ENTRY));
    }

    {
        info := type_info(FL_OBJECT_);
        for info.members {
            if it.name == {
                case "form";
                    assert(it.offset_in_bytes == 0, "FL_OBJECT_.form has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.form has unexpected size % instead of 8", it.type.runtime_size);
                case "u_vdata";
                    assert(it.offset_in_bytes == 8, "FL_OBJECT_.u_vdata has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.u_vdata has unexpected size % instead of 8", it.type.runtime_size);
                case "u_cdata";
                    assert(it.offset_in_bytes == 16, "FL_OBJECT_.u_cdata has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.u_cdata has unexpected size % instead of 8", it.type.runtime_size);
                case "u_ldata";
                    assert(it.offset_in_bytes == 24, "FL_OBJECT_.u_ldata has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.u_ldata has unexpected size % instead of 8", it.type.runtime_size);
                case "objclass";
                    assert(it.offset_in_bytes == 32, "FL_OBJECT_.objclass has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.objclass has unexpected size % instead of 4", it.type.runtime_size);
                case "type";
                    assert(it.offset_in_bytes == 36, "FL_OBJECT_.type has unexpected offset % instead of 36", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.type has unexpected size % instead of 4", it.type.runtime_size);
                case "boxtype";
                    assert(it.offset_in_bytes == 40, "FL_OBJECT_.boxtype has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.boxtype has unexpected size % instead of 4", it.type.runtime_size);
                case "x";
                    assert(it.offset_in_bytes == 44, "FL_OBJECT_.x has unexpected offset % instead of 44", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.x has unexpected size % instead of 4", it.type.runtime_size);
                case "y";
                    assert(it.offset_in_bytes == 48, "FL_OBJECT_.y has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.y has unexpected size % instead of 4", it.type.runtime_size);
                case "w";
                    assert(it.offset_in_bytes == 52, "FL_OBJECT_.w has unexpected offset % instead of 52", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.w has unexpected size % instead of 4", it.type.runtime_size);
                case "h";
                    assert(it.offset_in_bytes == 56, "FL_OBJECT_.h has unexpected offset % instead of 56", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.h has unexpected size % instead of 4", it.type.runtime_size);
                case "fl1";
                    assert(it.offset_in_bytes == 64, "FL_OBJECT_.fl1 has unexpected offset % instead of 64", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.fl1 has unexpected size % instead of 8", it.type.runtime_size);
                case "fr1";
                    assert(it.offset_in_bytes == 72, "FL_OBJECT_.fr1 has unexpected offset % instead of 72", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.fr1 has unexpected size % instead of 8", it.type.runtime_size);
                case "ft1";
                    assert(it.offset_in_bytes == 80, "FL_OBJECT_.ft1 has unexpected offset % instead of 80", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.ft1 has unexpected size % instead of 8", it.type.runtime_size);
                case "fb1";
                    assert(it.offset_in_bytes == 88, "FL_OBJECT_.fb1 has unexpected offset % instead of 88", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.fb1 has unexpected size % instead of 8", it.type.runtime_size);
                case "fl2";
                    assert(it.offset_in_bytes == 96, "FL_OBJECT_.fl2 has unexpected offset % instead of 96", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.fl2 has unexpected size % instead of 8", it.type.runtime_size);
                case "fr2";
                    assert(it.offset_in_bytes == 104, "FL_OBJECT_.fr2 has unexpected offset % instead of 104", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.fr2 has unexpected size % instead of 8", it.type.runtime_size);
                case "ft2";
                    assert(it.offset_in_bytes == 112, "FL_OBJECT_.ft2 has unexpected offset % instead of 112", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.ft2 has unexpected size % instead of 8", it.type.runtime_size);
                case "fb2";
                    assert(it.offset_in_bytes == 120, "FL_OBJECT_.fb2 has unexpected offset % instead of 120", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.fb2 has unexpected size % instead of 8", it.type.runtime_size);
                case "bw";
                    assert(it.offset_in_bytes == 128, "FL_OBJECT_.bw has unexpected offset % instead of 128", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.bw has unexpected size % instead of 4", it.type.runtime_size);
                case "col1";
                    assert(it.offset_in_bytes == 136, "FL_OBJECT_.col1 has unexpected offset % instead of 136", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.col1 has unexpected size % instead of 8", it.type.runtime_size);
                case "col2";
                    assert(it.offset_in_bytes == 144, "FL_OBJECT_.col2 has unexpected offset % instead of 144", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.col2 has unexpected size % instead of 8", it.type.runtime_size);
                case "label";
                    assert(it.offset_in_bytes == 152, "FL_OBJECT_.label has unexpected offset % instead of 152", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.label has unexpected size % instead of 8", it.type.runtime_size);
                case "lcol";
                    assert(it.offset_in_bytes == 160, "FL_OBJECT_.lcol has unexpected offset % instead of 160", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.lcol has unexpected size % instead of 8", it.type.runtime_size);
                case "align";
                    assert(it.offset_in_bytes == 168, "FL_OBJECT_.align has unexpected offset % instead of 168", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.align has unexpected size % instead of 4", it.type.runtime_size);
                case "lsize";
                    assert(it.offset_in_bytes == 172, "FL_OBJECT_.lsize has unexpected offset % instead of 172", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.lsize has unexpected size % instead of 4", it.type.runtime_size);
                case "lstyle";
                    assert(it.offset_in_bytes == 176, "FL_OBJECT_.lstyle has unexpected offset % instead of 176", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.lstyle has unexpected size % instead of 4", it.type.runtime_size);
                case "shortcut";
                    assert(it.offset_in_bytes == 184, "FL_OBJECT_.shortcut has unexpected offset % instead of 184", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.shortcut has unexpected size % instead of 8", it.type.runtime_size);
                case "handle";
                    assert(it.offset_in_bytes == 192, "FL_OBJECT_.handle has unexpected offset % instead of 192", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.handle has unexpected size % instead of 8", it.type.runtime_size);
                case "object_callback";
                    assert(it.offset_in_bytes == 200, "FL_OBJECT_.object_callback has unexpected offset % instead of 200", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.object_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "argument";
                    assert(it.offset_in_bytes == 208, "FL_OBJECT_.argument has unexpected offset % instead of 208", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.argument has unexpected size % instead of 8", it.type.runtime_size);
                case "spec";
                    assert(it.offset_in_bytes == 216, "FL_OBJECT_.spec has unexpected offset % instead of 216", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.spec has unexpected size % instead of 8", it.type.runtime_size);
                case "prehandle";
                    assert(it.offset_in_bytes == 224, "FL_OBJECT_.prehandle has unexpected offset % instead of 224", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.prehandle has unexpected size % instead of 8", it.type.runtime_size);
                case "posthandle";
                    assert(it.offset_in_bytes == 232, "FL_OBJECT_.posthandle has unexpected offset % instead of 232", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.posthandle has unexpected size % instead of 8", it.type.runtime_size);
                case "set_return";
                    assert(it.offset_in_bytes == 240, "FL_OBJECT_.set_return has unexpected offset % instead of 240", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.set_return has unexpected size % instead of 8", it.type.runtime_size);
                case "resize";
                    assert(it.offset_in_bytes == 248, "FL_OBJECT_.resize has unexpected offset % instead of 248", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.resize has unexpected size % instead of 4", it.type.runtime_size);
                case "nwgravity";
                    assert(it.offset_in_bytes == 252, "FL_OBJECT_.nwgravity has unexpected offset % instead of 252", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.nwgravity has unexpected size % instead of 4", it.type.runtime_size);
                case "segravity";
                    assert(it.offset_in_bytes == 256, "FL_OBJECT_.segravity has unexpected offset % instead of 256", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.segravity has unexpected size % instead of 4", it.type.runtime_size);
                case "prev";
                    assert(it.offset_in_bytes == 264, "FL_OBJECT_.prev has unexpected offset % instead of 264", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.prev has unexpected size % instead of 8", it.type.runtime_size);
                case "next";
                    assert(it.offset_in_bytes == 272, "FL_OBJECT_.next has unexpected offset % instead of 272", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.next has unexpected size % instead of 8", it.type.runtime_size);
                case "parent";
                    assert(it.offset_in_bytes == 280, "FL_OBJECT_.parent has unexpected offset % instead of 280", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.parent has unexpected size % instead of 8", it.type.runtime_size);
                case "child";
                    assert(it.offset_in_bytes == 288, "FL_OBJECT_.child has unexpected offset % instead of 288", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.child has unexpected size % instead of 8", it.type.runtime_size);
                case "nc";
                    assert(it.offset_in_bytes == 296, "FL_OBJECT_.nc has unexpected offset % instead of 296", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.nc has unexpected size % instead of 8", it.type.runtime_size);
                case "flpixmap";
                    assert(it.offset_in_bytes == 304, "FL_OBJECT_.flpixmap has unexpected offset % instead of 304", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.flpixmap has unexpected size % instead of 8", it.type.runtime_size);
                case "use_pixmap";
                    assert(it.offset_in_bytes == 312, "FL_OBJECT_.use_pixmap has unexpected offset % instead of 312", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.use_pixmap has unexpected size % instead of 4", it.type.runtime_size);
                case "returned";
                    assert(it.offset_in_bytes == 316, "FL_OBJECT_.returned has unexpected offset % instead of 316", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.returned has unexpected size % instead of 4", it.type.runtime_size);
                case "how_return";
                    assert(it.offset_in_bytes == 320, "FL_OBJECT_.how_return has unexpected offset % instead of 320", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.how_return has unexpected size % instead of 4", it.type.runtime_size);
                case "double_buffer";
                    assert(it.offset_in_bytes == 324, "FL_OBJECT_.double_buffer has unexpected offset % instead of 324", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.double_buffer has unexpected size % instead of 4", it.type.runtime_size);
                case "pushed";
                    assert(it.offset_in_bytes == 328, "FL_OBJECT_.pushed has unexpected offset % instead of 328", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.pushed has unexpected size % instead of 4", it.type.runtime_size);
                case "focus";
                    assert(it.offset_in_bytes == 332, "FL_OBJECT_.focus has unexpected offset % instead of 332", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.focus has unexpected size % instead of 4", it.type.runtime_size);
                case "belowmouse";
                    assert(it.offset_in_bytes == 336, "FL_OBJECT_.belowmouse has unexpected offset % instead of 336", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.belowmouse has unexpected size % instead of 4", it.type.runtime_size);
                case "active";
                    assert(it.offset_in_bytes == 340, "FL_OBJECT_.active has unexpected offset % instead of 340", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.active has unexpected size % instead of 4", it.type.runtime_size);
                case "input";
                    assert(it.offset_in_bytes == 344, "FL_OBJECT_.input has unexpected offset % instead of 344", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.input has unexpected size % instead of 4", it.type.runtime_size);
                case "wantkey";
                    assert(it.offset_in_bytes == 348, "FL_OBJECT_.wantkey has unexpected offset % instead of 348", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.wantkey has unexpected size % instead of 4", it.type.runtime_size);
                case "radio";
                    assert(it.offset_in_bytes == 352, "FL_OBJECT_.radio has unexpected offset % instead of 352", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.radio has unexpected size % instead of 4", it.type.runtime_size);
                case "automatic";
                    assert(it.offset_in_bytes == 356, "FL_OBJECT_.automatic has unexpected offset % instead of 356", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.automatic has unexpected size % instead of 4", it.type.runtime_size);
                case "redraw";
                    assert(it.offset_in_bytes == 360, "FL_OBJECT_.redraw has unexpected offset % instead of 360", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.redraw has unexpected size % instead of 4", it.type.runtime_size);
                case "visible";
                    assert(it.offset_in_bytes == 364, "FL_OBJECT_.visible has unexpected offset % instead of 364", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.visible has unexpected size % instead of 4", it.type.runtime_size);
                case "is_under";
                    assert(it.offset_in_bytes == 368, "FL_OBJECT_.is_under has unexpected offset % instead of 368", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.is_under has unexpected size % instead of 4", it.type.runtime_size);
                case "clip";
                    assert(it.offset_in_bytes == 372, "FL_OBJECT_.clip has unexpected offset % instead of 372", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.clip has unexpected size % instead of 4", it.type.runtime_size);
                case "click_timeout";
                    assert(it.offset_in_bytes == 376, "FL_OBJECT_.click_timeout has unexpected offset % instead of 376", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.click_timeout has unexpected size % instead of 8", it.type.runtime_size);
                case "c_vdata";
                    assert(it.offset_in_bytes == 384, "FL_OBJECT_.c_vdata has unexpected offset % instead of 384", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.c_vdata has unexpected size % instead of 8", it.type.runtime_size);
                case "c_cdata";
                    assert(it.offset_in_bytes == 392, "FL_OBJECT_.c_cdata has unexpected offset % instead of 392", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.c_cdata has unexpected size % instead of 8", it.type.runtime_size);
                case "c_ldata";
                    assert(it.offset_in_bytes == 400, "FL_OBJECT_.c_ldata has unexpected offset % instead of 400", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.c_ldata has unexpected size % instead of 8", it.type.runtime_size);
                case "dbl_background";
                    assert(it.offset_in_bytes == 408, "FL_OBJECT_.dbl_background has unexpected offset % instead of 408", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.dbl_background has unexpected size % instead of 8", it.type.runtime_size);
                case "tooltip";
                    assert(it.offset_in_bytes == 416, "FL_OBJECT_.tooltip has unexpected offset % instead of 416", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_OBJECT_.tooltip has unexpected size % instead of 8", it.type.runtime_size);
                case "tipID";
                    assert(it.offset_in_bytes == 424, "FL_OBJECT_.tipID has unexpected offset % instead of 424", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.tipID has unexpected size % instead of 4", it.type.runtime_size);
                case "group_id";
                    assert(it.offset_in_bytes == 428, "FL_OBJECT_.group_id has unexpected offset % instead of 428", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.group_id has unexpected size % instead of 4", it.type.runtime_size);
                case "want_motion";
                    assert(it.offset_in_bytes == 432, "FL_OBJECT_.want_motion has unexpected offset % instead of 432", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.want_motion has unexpected size % instead of 4", it.type.runtime_size);
                case "want_update";
                    assert(it.offset_in_bytes == 436, "FL_OBJECT_.want_update has unexpected offset % instead of 436", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_OBJECT_.want_update has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(FL_OBJECT_) == 440, "FL_OBJECT_ has size % instead of 440", size_of(FL_OBJECT_));
    }

    {
        info := type_info(FL_FORM_);
        for info.members {
            if it.name == {
                case "fdui";
                    assert(it.offset_in_bytes == 0, "FL_FORM_.fdui has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.fdui has unexpected size % instead of 8", it.type.runtime_size);
                case "u_vdata";
                    assert(it.offset_in_bytes == 8, "FL_FORM_.u_vdata has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.u_vdata has unexpected size % instead of 8", it.type.runtime_size);
                case "u_cdata";
                    assert(it.offset_in_bytes == 16, "FL_FORM_.u_cdata has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.u_cdata has unexpected size % instead of 8", it.type.runtime_size);
                case "u_ldata";
                    assert(it.offset_in_bytes == 24, "FL_FORM_.u_ldata has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.u_ldata has unexpected size % instead of 8", it.type.runtime_size);
                case "label";
                    assert(it.offset_in_bytes == 32, "FL_FORM_.label has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.label has unexpected size % instead of 8", it.type.runtime_size);
                case "window";
                    assert(it.offset_in_bytes == 40, "FL_FORM_.window has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.window has unexpected size % instead of 8", it.type.runtime_size);
                case "x";
                    assert(it.offset_in_bytes == 48, "FL_FORM_.x has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.x has unexpected size % instead of 4", it.type.runtime_size);
                case "y";
                    assert(it.offset_in_bytes == 52, "FL_FORM_.y has unexpected offset % instead of 52", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.y has unexpected size % instead of 4", it.type.runtime_size);
                case "w";
                    assert(it.offset_in_bytes == 56, "FL_FORM_.w has unexpected offset % instead of 56", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.w has unexpected size % instead of 4", it.type.runtime_size);
                case "h";
                    assert(it.offset_in_bytes == 60, "FL_FORM_.h has unexpected offset % instead of 60", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.h has unexpected size % instead of 4", it.type.runtime_size);
                case "handle_dec_x";
                    assert(it.offset_in_bytes == 64, "FL_FORM_.handle_dec_x has unexpected offset % instead of 64", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.handle_dec_x has unexpected size % instead of 4", it.type.runtime_size);
                case "handle_dec_y";
                    assert(it.offset_in_bytes == 68, "FL_FORM_.handle_dec_y has unexpected offset % instead of 68", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.handle_dec_y has unexpected size % instead of 4", it.type.runtime_size);
                case "hotx";
                    assert(it.offset_in_bytes == 72, "FL_FORM_.hotx has unexpected offset % instead of 72", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.hotx has unexpected size % instead of 4", it.type.runtime_size);
                case "hoty";
                    assert(it.offset_in_bytes == 76, "FL_FORM_.hoty has unexpected offset % instead of 76", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.hoty has unexpected size % instead of 4", it.type.runtime_size);
                case "w_hr";
                    assert(it.offset_in_bytes == 80, "FL_FORM_.w_hr has unexpected offset % instead of 80", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.w_hr has unexpected size % instead of 8", it.type.runtime_size);
                case "h_hr";
                    assert(it.offset_in_bytes == 88, "FL_FORM_.h_hr has unexpected offset % instead of 88", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.h_hr has unexpected size % instead of 8", it.type.runtime_size);
                case "first";
                    assert(it.offset_in_bytes == 96, "FL_FORM_.first has unexpected offset % instead of 96", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.first has unexpected size % instead of 8", it.type.runtime_size);
                case "last";
                    assert(it.offset_in_bytes == 104, "FL_FORM_.last has unexpected offset % instead of 104", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.last has unexpected size % instead of 8", it.type.runtime_size);
                case "focusobj";
                    assert(it.offset_in_bytes == 112, "FL_FORM_.focusobj has unexpected offset % instead of 112", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.focusobj has unexpected size % instead of 8", it.type.runtime_size);
                case "form_callback";
                    assert(it.offset_in_bytes == 120, "FL_FORM_.form_callback has unexpected offset % instead of 120", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.form_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "activate_callback";
                    assert(it.offset_in_bytes == 128, "FL_FORM_.activate_callback has unexpected offset % instead of 128", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.activate_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "deactivate_callback";
                    assert(it.offset_in_bytes == 136, "FL_FORM_.deactivate_callback has unexpected offset % instead of 136", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.deactivate_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "form_cb_data";
                    assert(it.offset_in_bytes == 144, "FL_FORM_.form_cb_data has unexpected offset % instead of 144", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.form_cb_data has unexpected size % instead of 8", it.type.runtime_size);
                case "activate_data";
                    assert(it.offset_in_bytes == 152, "FL_FORM_.activate_data has unexpected offset % instead of 152", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.activate_data has unexpected size % instead of 8", it.type.runtime_size);
                case "deactivate_data";
                    assert(it.offset_in_bytes == 160, "FL_FORM_.deactivate_data has unexpected offset % instead of 160", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.deactivate_data has unexpected size % instead of 8", it.type.runtime_size);
                case "key_callback";
                    assert(it.offset_in_bytes == 168, "FL_FORM_.key_callback has unexpected offset % instead of 168", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.key_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "push_callback";
                    assert(it.offset_in_bytes == 176, "FL_FORM_.push_callback has unexpected offset % instead of 176", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.push_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "crossing_callback";
                    assert(it.offset_in_bytes == 184, "FL_FORM_.crossing_callback has unexpected offset % instead of 184", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.crossing_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "motion_callback";
                    assert(it.offset_in_bytes == 192, "FL_FORM_.motion_callback has unexpected offset % instead of 192", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.motion_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "all_callback";
                    assert(it.offset_in_bytes == 200, "FL_FORM_.all_callback has unexpected offset % instead of 200", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.all_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "compress_mask";
                    assert(it.offset_in_bytes == 208, "FL_FORM_.compress_mask has unexpected offset % instead of 208", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.compress_mask has unexpected size % instead of 8", it.type.runtime_size);
                case "evmask";
                    assert(it.offset_in_bytes == 216, "FL_FORM_.evmask has unexpected offset % instead of 216", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.evmask has unexpected size % instead of 8", it.type.runtime_size);
                case "close_callback";
                    assert(it.offset_in_bytes == 224, "FL_FORM_.close_callback has unexpected offset % instead of 224", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.close_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "close_data";
                    assert(it.offset_in_bytes == 232, "FL_FORM_.close_data has unexpected offset % instead of 232", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.close_data has unexpected size % instead of 8", it.type.runtime_size);
                case "flpixmap";
                    assert(it.offset_in_bytes == 240, "FL_FORM_.flpixmap has unexpected offset % instead of 240", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.flpixmap has unexpected size % instead of 8", it.type.runtime_size);
                case "icon_pixmap";
                    assert(it.offset_in_bytes == 248, "FL_FORM_.icon_pixmap has unexpected offset % instead of 248", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.icon_pixmap has unexpected size % instead of 8", it.type.runtime_size);
                case "icon_mask";
                    assert(it.offset_in_bytes == 256, "FL_FORM_.icon_mask has unexpected offset % instead of 256", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.icon_mask has unexpected size % instead of 8", it.type.runtime_size);
                case "deactivated";
                    assert(it.offset_in_bytes == 264, "FL_FORM_.deactivated has unexpected offset % instead of 264", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.deactivated has unexpected size % instead of 4", it.type.runtime_size);
                case "use_pixmap";
                    assert(it.offset_in_bytes == 268, "FL_FORM_.use_pixmap has unexpected offset % instead of 268", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.use_pixmap has unexpected size % instead of 4", it.type.runtime_size);
                case "frozen";
                    assert(it.offset_in_bytes == 272, "FL_FORM_.frozen has unexpected offset % instead of 272", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.frozen has unexpected size % instead of 4", it.type.runtime_size);
                case "visible";
                    assert(it.offset_in_bytes == 276, "FL_FORM_.visible has unexpected offset % instead of 276", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.visible has unexpected size % instead of 4", it.type.runtime_size);
                case "wm_border";
                    assert(it.offset_in_bytes == 280, "FL_FORM_.wm_border has unexpected offset % instead of 280", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.wm_border has unexpected size % instead of 4", it.type.runtime_size);
                case "prop";
                    assert(it.offset_in_bytes == 284, "FL_FORM_.prop has unexpected offset % instead of 284", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.prop has unexpected size % instead of 4", it.type.runtime_size);
                case "num_auto_objects";
                    assert(it.offset_in_bytes == 288, "FL_FORM_.num_auto_objects has unexpected offset % instead of 288", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.num_auto_objects has unexpected size % instead of 4", it.type.runtime_size);
                case "needs_full_redraw";
                    assert(it.offset_in_bytes == 292, "FL_FORM_.needs_full_redraw has unexpected offset % instead of 292", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.needs_full_redraw has unexpected size % instead of 4", it.type.runtime_size);
                case "sort_of_modal";
                    assert(it.offset_in_bytes == 296, "FL_FORM_.sort_of_modal has unexpected offset % instead of 296", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.sort_of_modal has unexpected size % instead of 4", it.type.runtime_size);
                case "parent";
                    assert(it.offset_in_bytes == 304, "FL_FORM_.parent has unexpected offset % instead of 304", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.parent has unexpected size % instead of 8", it.type.runtime_size);
                case "child";
                    assert(it.offset_in_bytes == 312, "FL_FORM_.child has unexpected offset % instead of 312", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.child has unexpected size % instead of 8", it.type.runtime_size);
                case "parent_obj";
                    assert(it.offset_in_bytes == 320, "FL_FORM_.parent_obj has unexpected offset % instead of 320", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.parent_obj has unexpected size % instead of 8", it.type.runtime_size);
                case "attached";
                    assert(it.offset_in_bytes == 328, "FL_FORM_.attached has unexpected offset % instead of 328", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.attached has unexpected size % instead of 4", it.type.runtime_size);
                case "pre_attach";
                    assert(it.offset_in_bytes == 336, "FL_FORM_.pre_attach has unexpected offset % instead of 336", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.pre_attach has unexpected size % instead of 8", it.type.runtime_size);
                case "attach_data";
                    assert(it.offset_in_bytes == 344, "FL_FORM_.attach_data has unexpected offset % instead of 344", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_FORM_.attach_data has unexpected size % instead of 8", it.type.runtime_size);
                case "in_redraw";
                    assert(it.offset_in_bytes == 352, "FL_FORM_.in_redraw has unexpected offset % instead of 352", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_FORM_.in_redraw has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(FL_FORM_) == 360, "FL_FORM_ has size % instead of 360", size_of(FL_FORM_));
    }

    {
        info := type_info(FD_Any);
        for info.members {
            if it.name == {
                case "form";
                    assert(it.offset_in_bytes == 0, "FD_Any.form has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_Any.form has unexpected size % instead of 8", it.type.runtime_size);
                case "vdata";
                    assert(it.offset_in_bytes == 8, "FD_Any.vdata has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_Any.vdata has unexpected size % instead of 8", it.type.runtime_size);
                case "cdata";
                    assert(it.offset_in_bytes == 16, "FD_Any.cdata has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_Any.cdata has unexpected size % instead of 8", it.type.runtime_size);
                case "ldata";
                    assert(it.offset_in_bytes == 24, "FD_Any.ldata has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_Any.ldata has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(FD_Any) == 32, "FD_Any has size % instead of 32", size_of(FD_Any));
    }

    {
        info := type_info(FL_State);
        for info.members {
            if it.name == {
                case "xvinfo";
                    assert(it.offset_in_bytes == 0, "FL_State.xvinfo has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_State.xvinfo has unexpected size % instead of 8", it.type.runtime_size);
                case "cur_fnt";
                    assert(it.offset_in_bytes == 8, "FL_State.cur_fnt has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_State.cur_fnt has unexpected size % instead of 8", it.type.runtime_size);
                case "colormap";
                    assert(it.offset_in_bytes == 16, "FL_State.colormap has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_State.colormap has unexpected size % instead of 8", it.type.runtime_size);
                case "trailblazer";
                    assert(it.offset_in_bytes == 24, "FL_State.trailblazer has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_State.trailblazer has unexpected size % instead of 8", it.type.runtime_size);
                case "vclass";
                    assert(it.offset_in_bytes == 32, "FL_State.vclass has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.vclass has unexpected size % instead of 4", it.type.runtime_size);
                case "depth";
                    assert(it.offset_in_bytes == 36, "FL_State.depth has unexpected offset % instead of 36", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.depth has unexpected size % instead of 4", it.type.runtime_size);
                case "rgb_bits";
                    assert(it.offset_in_bytes == 40, "FL_State.rgb_bits has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.rgb_bits has unexpected size % instead of 4", it.type.runtime_size);
                case "dithered";
                    assert(it.offset_in_bytes == 44, "FL_State.dithered has unexpected offset % instead of 44", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.dithered has unexpected size % instead of 4", it.type.runtime_size);
                case "pcm";
                    assert(it.offset_in_bytes == 48, "FL_State.pcm has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.pcm has unexpected size % instead of 4", it.type.runtime_size);
                case "gc";
                    assert(it.offset_in_bytes == 56, "FL_State.gc has unexpected offset % instead of 56", it.offset_in_bytes);
                    assert(it.type.runtime_size == 128, "FL_State.gc has unexpected size % instead of 128", it.type.runtime_size);
                case "textgc";
                    assert(it.offset_in_bytes == 184, "FL_State.textgc has unexpected offset % instead of 184", it.offset_in_bytes);
                    assert(it.type.runtime_size == 128, "FL_State.textgc has unexpected size % instead of 128", it.type.runtime_size);
                case "dimmedGC";
                    assert(it.offset_in_bytes == 312, "FL_State.dimmedGC has unexpected offset % instead of 312", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_State.dimmedGC has unexpected size % instead of 8", it.type.runtime_size);
                case "lut";
                    assert(it.offset_in_bytes == 320, "FL_State.lut has unexpected offset % instead of 320", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8192, "FL_State.lut has unexpected size % instead of 8192", it.type.runtime_size);
                case "rshift";
                    assert(it.offset_in_bytes == 8512, "FL_State.rshift has unexpected offset % instead of 8512", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.rshift has unexpected size % instead of 4", it.type.runtime_size);
                case "rmask";
                    assert(it.offset_in_bytes == 8516, "FL_State.rmask has unexpected offset % instead of 8516", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.rmask has unexpected size % instead of 4", it.type.runtime_size);
                case "rbits";
                    assert(it.offset_in_bytes == 8520, "FL_State.rbits has unexpected offset % instead of 8520", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.rbits has unexpected size % instead of 4", it.type.runtime_size);
                case "gshift";
                    assert(it.offset_in_bytes == 8524, "FL_State.gshift has unexpected offset % instead of 8524", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.gshift has unexpected size % instead of 4", it.type.runtime_size);
                case "gmask";
                    assert(it.offset_in_bytes == 8528, "FL_State.gmask has unexpected offset % instead of 8528", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.gmask has unexpected size % instead of 4", it.type.runtime_size);
                case "gbits";
                    assert(it.offset_in_bytes == 8532, "FL_State.gbits has unexpected offset % instead of 8532", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.gbits has unexpected size % instead of 4", it.type.runtime_size);
                case "bshift";
                    assert(it.offset_in_bytes == 8536, "FL_State.bshift has unexpected offset % instead of 8536", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.bshift has unexpected size % instead of 4", it.type.runtime_size);
                case "bmask";
                    assert(it.offset_in_bytes == 8540, "FL_State.bmask has unexpected offset % instead of 8540", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.bmask has unexpected size % instead of 4", it.type.runtime_size);
                case "bbits";
                    assert(it.offset_in_bytes == 8544, "FL_State.bbits has unexpected offset % instead of 8544", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_State.bbits has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(FL_State) == 8552, "FL_State has size % instead of 8552", size_of(FL_State));
    }

    {
        info := type_info(FL_pixmap_);
        for info.members {
            if it.name == {
                case "pixmap";
                    assert(it.offset_in_bytes == 0, "FL_pixmap_.pixmap has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_pixmap_.pixmap has unexpected size % instead of 8", it.type.runtime_size);
                case "win";
                    assert(it.offset_in_bytes == 8, "FL_pixmap_.win has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_pixmap_.win has unexpected size % instead of 8", it.type.runtime_size);
                case "visual";
                    assert(it.offset_in_bytes == 16, "FL_pixmap_.visual has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_pixmap_.visual has unexpected size % instead of 8", it.type.runtime_size);
                case "x";
                    assert(it.offset_in_bytes == 24, "FL_pixmap_.x has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_pixmap_.x has unexpected size % instead of 4", it.type.runtime_size);
                case "y";
                    assert(it.offset_in_bytes == 28, "FL_pixmap_.y has unexpected offset % instead of 28", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_pixmap_.y has unexpected size % instead of 4", it.type.runtime_size);
                case "w";
                    assert(it.offset_in_bytes == 32, "FL_pixmap_.w has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_pixmap_.w has unexpected size % instead of 4", it.type.runtime_size);
                case "h";
                    assert(it.offset_in_bytes == 36, "FL_pixmap_.h has unexpected offset % instead of 36", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_pixmap_.h has unexpected size % instead of 4", it.type.runtime_size);
                case "depth";
                    assert(it.offset_in_bytes == 40, "FL_pixmap_.depth has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_pixmap_.depth has unexpected size % instead of 4", it.type.runtime_size);
                case "dbl_background";
                    assert(it.offset_in_bytes == 48, "FL_pixmap_.dbl_background has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_pixmap_.dbl_background has unexpected size % instead of 8", it.type.runtime_size);
                case "pixel";
                    assert(it.offset_in_bytes == 56, "FL_pixmap_.pixel has unexpected offset % instead of 56", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_pixmap_.pixel has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(FL_pixmap_) == 64, "FL_pixmap_ has size % instead of 64", size_of(FL_pixmap_));
    }

    {
        info := type_info(FL_FONT);
        for info.members {
            if it.name == {
                case "fs";
                    assert(it.offset_in_bytes == 0, "FL_FONT.fs has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 80, "FL_FONT.fs has unexpected size % instead of 80", it.type.runtime_size);
                case "size";
                    assert(it.offset_in_bytes == 80, "FL_FONT.size has unexpected offset % instead of 80", it.offset_in_bytes);
                    assert(it.type.runtime_size == 20, "FL_FONT.size has unexpected size % instead of 20", it.type.runtime_size);
                case "nsize";
                    assert(it.offset_in_bytes == 100, "FL_FONT.nsize has unexpected offset % instead of 100", it.offset_in_bytes);
                    assert(it.type.runtime_size == 2, "FL_FONT.nsize has unexpected size % instead of 2", it.type.runtime_size);
                case "fname";
                    assert(it.offset_in_bytes == 102, "FL_FONT.fname has unexpected offset % instead of 102", it.offset_in_bytes);
                    assert(it.type.runtime_size == 81, "FL_FONT.fname has unexpected size % instead of 81", it.type.runtime_size);
            }
        }
        assert(size_of(FL_FONT) == 184, "FL_FONT has size % instead of 184", size_of(FL_FONT));
    }

    {
        info := type_info(FL_RESOURCE);
        for info.members {
            if it.name == {
                case "res_name";
                    assert(it.offset_in_bytes == 0, "FL_RESOURCE.res_name has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_RESOURCE.res_name has unexpected size % instead of 8", it.type.runtime_size);
                case "res_class";
                    assert(it.offset_in_bytes == 8, "FL_RESOURCE.res_class has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_RESOURCE.res_class has unexpected size % instead of 8", it.type.runtime_size);
                case "type";
                    assert(it.offset_in_bytes == 16, "FL_RESOURCE.type has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RESOURCE.type has unexpected size % instead of 4", it.type.runtime_size);
                case "var";
                    assert(it.offset_in_bytes == 24, "FL_RESOURCE.var has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_RESOURCE.var has unexpected size % instead of 8", it.type.runtime_size);
                case "defval";
                    assert(it.offset_in_bytes == 32, "FL_RESOURCE.defval has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_RESOURCE.defval has unexpected size % instead of 8", it.type.runtime_size);
                case "nbytes";
                    assert(it.offset_in_bytes == 40, "FL_RESOURCE.nbytes has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RESOURCE.nbytes has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(FL_RESOURCE) == 48, "FL_RESOURCE has size % instead of 48", size_of(FL_RESOURCE));
    }

    {
        info := type_info(FL_IOPT);
        for info.members {
            if it.name == {
                case "rgamma";
                    assert(it.offset_in_bytes == 0, "FL_IOPT.rgamma has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.rgamma has unexpected size % instead of 4", it.type.runtime_size);
                case "ggamma";
                    assert(it.offset_in_bytes == 4, "FL_IOPT.ggamma has unexpected offset % instead of 4", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.ggamma has unexpected size % instead of 4", it.type.runtime_size);
                case "bgamma";
                    assert(it.offset_in_bytes == 8, "FL_IOPT.bgamma has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.bgamma has unexpected size % instead of 4", it.type.runtime_size);
                case "debug";
                    assert(it.offset_in_bytes == 12, "FL_IOPT.debug has unexpected offset % instead of 12", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.debug has unexpected size % instead of 4", it.type.runtime_size);
                case "sync";
                    assert(it.offset_in_bytes == 16, "FL_IOPT.sync has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.sync has unexpected size % instead of 4", it.type.runtime_size);
                case "depth";
                    assert(it.offset_in_bytes == 20, "FL_IOPT.depth has unexpected offset % instead of 20", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.depth has unexpected size % instead of 4", it.type.runtime_size);
                case "vclass";
                    assert(it.offset_in_bytes == 24, "FL_IOPT.vclass has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.vclass has unexpected size % instead of 4", it.type.runtime_size);
                case "doubleBuffer";
                    assert(it.offset_in_bytes == 28, "FL_IOPT.doubleBuffer has unexpected offset % instead of 28", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.doubleBuffer has unexpected size % instead of 4", it.type.runtime_size);
                case "ulPropWidth";
                    assert(it.offset_in_bytes == 32, "FL_IOPT.ulPropWidth has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.ulPropWidth has unexpected size % instead of 4", it.type.runtime_size);
                case "ulThickness";
                    assert(it.offset_in_bytes == 36, "FL_IOPT.ulThickness has unexpected offset % instead of 36", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.ulThickness has unexpected size % instead of 4", it.type.runtime_size);
                case "buttonFontSize";
                    assert(it.offset_in_bytes == 40, "FL_IOPT.buttonFontSize has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.buttonFontSize has unexpected size % instead of 4", it.type.runtime_size);
                case "sliderFontSize";
                    assert(it.offset_in_bytes == 44, "FL_IOPT.sliderFontSize has unexpected offset % instead of 44", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.sliderFontSize has unexpected size % instead of 4", it.type.runtime_size);
                case "inputFontSize";
                    assert(it.offset_in_bytes == 48, "FL_IOPT.inputFontSize has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.inputFontSize has unexpected size % instead of 4", it.type.runtime_size);
                case "browserFontSize";
                    assert(it.offset_in_bytes == 52, "FL_IOPT.browserFontSize has unexpected offset % instead of 52", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.browserFontSize has unexpected size % instead of 4", it.type.runtime_size);
                case "menuFontSize";
                    assert(it.offset_in_bytes == 56, "FL_IOPT.menuFontSize has unexpected offset % instead of 56", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.menuFontSize has unexpected size % instead of 4", it.type.runtime_size);
                case "choiceFontSize";
                    assert(it.offset_in_bytes == 60, "FL_IOPT.choiceFontSize has unexpected offset % instead of 60", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.choiceFontSize has unexpected size % instead of 4", it.type.runtime_size);
                case "labelFontSize";
                    assert(it.offset_in_bytes == 64, "FL_IOPT.labelFontSize has unexpected offset % instead of 64", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.labelFontSize has unexpected size % instead of 4", it.type.runtime_size);
                case "pupFontSize";
                    assert(it.offset_in_bytes == 68, "FL_IOPT.pupFontSize has unexpected offset % instead of 68", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.pupFontSize has unexpected size % instead of 4", it.type.runtime_size);
                case "pupFontStyle";
                    assert(it.offset_in_bytes == 72, "FL_IOPT.pupFontStyle has unexpected offset % instead of 72", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.pupFontStyle has unexpected size % instead of 4", it.type.runtime_size);
                case "privateColormap";
                    assert(it.offset_in_bytes == 76, "FL_IOPT.privateColormap has unexpected offset % instead of 76", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.privateColormap has unexpected size % instead of 4", it.type.runtime_size);
                case "sharedColormap";
                    assert(it.offset_in_bytes == 80, "FL_IOPT.sharedColormap has unexpected offset % instead of 80", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.sharedColormap has unexpected size % instead of 4", it.type.runtime_size);
                case "standardColormap";
                    assert(it.offset_in_bytes == 84, "FL_IOPT.standardColormap has unexpected offset % instead of 84", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.standardColormap has unexpected size % instead of 4", it.type.runtime_size);
                case "scrollbarType";
                    assert(it.offset_in_bytes == 88, "FL_IOPT.scrollbarType has unexpected offset % instead of 88", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.scrollbarType has unexpected size % instead of 4", it.type.runtime_size);
                case "backingStore";
                    assert(it.offset_in_bytes == 92, "FL_IOPT.backingStore has unexpected offset % instead of 92", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.backingStore has unexpected size % instead of 4", it.type.runtime_size);
                case "coordUnit";
                    assert(it.offset_in_bytes == 96, "FL_IOPT.coordUnit has unexpected offset % instead of 96", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.coordUnit has unexpected size % instead of 4", it.type.runtime_size);
                case "borderWidth";
                    assert(it.offset_in_bytes == 100, "FL_IOPT.borderWidth has unexpected offset % instead of 100", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.borderWidth has unexpected size % instead of 4", it.type.runtime_size);
                case "safe";
                    assert(it.offset_in_bytes == 104, "FL_IOPT.safe has unexpected offset % instead of 104", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_IOPT.safe has unexpected size % instead of 4", it.type.runtime_size);
                case "rgbfile";
                    assert(it.offset_in_bytes == 112, "FL_IOPT.rgbfile has unexpected offset % instead of 112", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_IOPT.rgbfile has unexpected size % instead of 8", it.type.runtime_size);
                case "vname";
                    assert(it.offset_in_bytes == 120, "FL_IOPT.vname has unexpected offset % instead of 120", it.offset_in_bytes);
                    assert(it.type.runtime_size == 24, "FL_IOPT.vname has unexpected size % instead of 24", it.type.runtime_size);
            }
        }
        assert(size_of(FL_IOPT) == 144, "FL_IOPT has size % instead of 144", size_of(FL_IOPT));
    }

    {
        info := type_info(FL_RGB2PIXEL_);
        for info.members {
            if it.name == {
                case "rshift";
                    assert(it.offset_in_bytes == 0, "FL_RGB2PIXEL_.rshift has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RGB2PIXEL_.rshift has unexpected size % instead of 4", it.type.runtime_size);
                case "rmask";
                    assert(it.offset_in_bytes == 4, "FL_RGB2PIXEL_.rmask has unexpected offset % instead of 4", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RGB2PIXEL_.rmask has unexpected size % instead of 4", it.type.runtime_size);
                case "rbits";
                    assert(it.offset_in_bytes == 8, "FL_RGB2PIXEL_.rbits has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RGB2PIXEL_.rbits has unexpected size % instead of 4", it.type.runtime_size);
                case "gshift";
                    assert(it.offset_in_bytes == 12, "FL_RGB2PIXEL_.gshift has unexpected offset % instead of 12", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RGB2PIXEL_.gshift has unexpected size % instead of 4", it.type.runtime_size);
                case "gmask";
                    assert(it.offset_in_bytes == 16, "FL_RGB2PIXEL_.gmask has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RGB2PIXEL_.gmask has unexpected size % instead of 4", it.type.runtime_size);
                case "gbits";
                    assert(it.offset_in_bytes == 20, "FL_RGB2PIXEL_.gbits has unexpected offset % instead of 20", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RGB2PIXEL_.gbits has unexpected size % instead of 4", it.type.runtime_size);
                case "bshift";
                    assert(it.offset_in_bytes == 24, "FL_RGB2PIXEL_.bshift has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RGB2PIXEL_.bshift has unexpected size % instead of 4", it.type.runtime_size);
                case "bmask";
                    assert(it.offset_in_bytes == 28, "FL_RGB2PIXEL_.bmask has unexpected offset % instead of 28", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RGB2PIXEL_.bmask has unexpected size % instead of 4", it.type.runtime_size);
                case "bbits";
                    assert(it.offset_in_bytes == 32, "FL_RGB2PIXEL_.bbits has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RGB2PIXEL_.bbits has unexpected size % instead of 4", it.type.runtime_size);
                case "bits_per_rgb";
                    assert(it.offset_in_bytes == 36, "FL_RGB2PIXEL_.bits_per_rgb has unexpected offset % instead of 36", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RGB2PIXEL_.bits_per_rgb has unexpected size % instead of 4", it.type.runtime_size);
                case "colormap_size";
                    assert(it.offset_in_bytes == 40, "FL_RGB2PIXEL_.colormap_size has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_RGB2PIXEL_.colormap_size has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(FL_RGB2PIXEL_) == 44, "FL_RGB2PIXEL_ has size % instead of 44", size_of(FL_RGB2PIXEL_));
    }

    {
        info := type_info(FL_POPUP_RETURN_);
        for info.members {
            if it.name == {
                case "val";
                    assert(it.offset_in_bytes == 0, "FL_POPUP_RETURN_.val has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_RETURN_.val has unexpected size % instead of 8", it.type.runtime_size);
                case "user_data";
                    assert(it.offset_in_bytes == 8, "FL_POPUP_RETURN_.user_data has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_RETURN_.user_data has unexpected size % instead of 8", it.type.runtime_size);
                case "text";
                    assert(it.offset_in_bytes == 16, "FL_POPUP_RETURN_.text has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_RETURN_.text has unexpected size % instead of 8", it.type.runtime_size);
                case "label";
                    assert(it.offset_in_bytes == 24, "FL_POPUP_RETURN_.label has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_RETURN_.label has unexpected size % instead of 8", it.type.runtime_size);
                case "accel";
                    assert(it.offset_in_bytes == 32, "FL_POPUP_RETURN_.accel has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_RETURN_.accel has unexpected size % instead of 8", it.type.runtime_size);
                case "entry";
                    assert(it.offset_in_bytes == 40, "FL_POPUP_RETURN_.entry has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_RETURN_.entry has unexpected size % instead of 8", it.type.runtime_size);
                case "popup";
                    assert(it.offset_in_bytes == 48, "FL_POPUP_RETURN_.popup has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_RETURN_.popup has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(FL_POPUP_RETURN_) == 56, "FL_POPUP_RETURN_ has size % instead of 56", size_of(FL_POPUP_RETURN_));
    }

    {
        info := type_info(FL_POPUP_);
        for info.members {
            if it.name == {
                case "next";
                    assert(it.offset_in_bytes == 0, "FL_POPUP_.next has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.next has unexpected size % instead of 8", it.type.runtime_size);
                case "prev";
                    assert(it.offset_in_bytes == 8, "FL_POPUP_.prev has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.prev has unexpected size % instead of 8", it.type.runtime_size);
                case "parent";
                    assert(it.offset_in_bytes == 16, "FL_POPUP_.parent has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.parent has unexpected size % instead of 8", it.type.runtime_size);
                case "top_parent";
                    assert(it.offset_in_bytes == 24, "FL_POPUP_.top_parent has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.top_parent has unexpected size % instead of 8", it.type.runtime_size);
                case "entries";
                    assert(it.offset_in_bytes == 32, "FL_POPUP_.entries has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.entries has unexpected size % instead of 8", it.type.runtime_size);
                case "title";
                    assert(it.offset_in_bytes == 40, "FL_POPUP_.title has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.title has unexpected size % instead of 8", it.type.runtime_size);
                case "win";
                    assert(it.offset_in_bytes == 48, "FL_POPUP_.win has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.win has unexpected size % instead of 8", it.type.runtime_size);
                case "parent_win";
                    assert(it.offset_in_bytes == 56, "FL_POPUP_.parent_win has unexpected offset % instead of 56", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.parent_win has unexpected size % instead of 8", it.type.runtime_size);
                case "cursor";
                    assert(it.offset_in_bytes == 64, "FL_POPUP_.cursor has unexpected offset % instead of 64", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.cursor has unexpected size % instead of 8", it.type.runtime_size);
                case "callback";
                    assert(it.offset_in_bytes == 72, "FL_POPUP_.callback has unexpected offset % instead of 72", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.callback has unexpected size % instead of 8", it.type.runtime_size);
                case "use_req_pos";
                    assert(it.offset_in_bytes == 80, "FL_POPUP_.use_req_pos has unexpected offset % instead of 80", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.use_req_pos has unexpected size % instead of 4", it.type.runtime_size);
                case "req_x";
                    assert(it.offset_in_bytes == 84, "FL_POPUP_.req_x has unexpected offset % instead of 84", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.req_x has unexpected size % instead of 4", it.type.runtime_size);
                case "req_y";
                    assert(it.offset_in_bytes == 88, "FL_POPUP_.req_y has unexpected offset % instead of 88", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.req_y has unexpected size % instead of 4", it.type.runtime_size);
                case "x";
                    assert(it.offset_in_bytes == 92, "FL_POPUP_.x has unexpected offset % instead of 92", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.x has unexpected size % instead of 4", it.type.runtime_size);
                case "y";
                    assert(it.offset_in_bytes == 96, "FL_POPUP_.y has unexpected offset % instead of 96", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.y has unexpected size % instead of 4", it.type.runtime_size);
                case "w";
                    assert(it.offset_in_bytes == 100, "FL_POPUP_.w has unexpected offset % instead of 100", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.w has unexpected size % instead of 4", it.type.runtime_size);
                case "h";
                    assert(it.offset_in_bytes == 104, "FL_POPUP_.h has unexpected offset % instead of 104", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.h has unexpected size % instead of 4", it.type.runtime_size);
                case "min_width";
                    assert(it.offset_in_bytes == 108, "FL_POPUP_.min_width has unexpected offset % instead of 108", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.min_width has unexpected size % instead of 4", it.type.runtime_size);
                case "title_box_x";
                    assert(it.offset_in_bytes == 112, "FL_POPUP_.title_box_x has unexpected offset % instead of 112", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.title_box_x has unexpected size % instead of 4", it.type.runtime_size);
                case "title_box_y";
                    assert(it.offset_in_bytes == 116, "FL_POPUP_.title_box_y has unexpected offset % instead of 116", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.title_box_y has unexpected size % instead of 4", it.type.runtime_size);
                case "title_box_w";
                    assert(it.offset_in_bytes == 120, "FL_POPUP_.title_box_w has unexpected offset % instead of 120", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.title_box_w has unexpected size % instead of 4", it.type.runtime_size);
                case "title_box_h";
                    assert(it.offset_in_bytes == 124, "FL_POPUP_.title_box_h has unexpected offset % instead of 124", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.title_box_h has unexpected size % instead of 4", it.type.runtime_size);
                case "has_subs";
                    assert(it.offset_in_bytes == 128, "FL_POPUP_.has_subs has unexpected offset % instead of 128", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.has_subs has unexpected size % instead of 4", it.type.runtime_size);
                case "has_boxes";
                    assert(it.offset_in_bytes == 132, "FL_POPUP_.has_boxes has unexpected offset % instead of 132", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.has_boxes has unexpected size % instead of 4", it.type.runtime_size);
                case "counter";
                    assert(it.offset_in_bytes == 136, "FL_POPUP_.counter has unexpected offset % instead of 136", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.counter has unexpected size % instead of 4", it.type.runtime_size);
                case "title_font_style";
                    assert(it.offset_in_bytes == 140, "FL_POPUP_.title_font_style has unexpected offset % instead of 140", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.title_font_style has unexpected size % instead of 4", it.type.runtime_size);
                case "title_font_size";
                    assert(it.offset_in_bytes == 144, "FL_POPUP_.title_font_size has unexpected offset % instead of 144", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.title_font_size has unexpected size % instead of 4", it.type.runtime_size);
                case "entry_font_style";
                    assert(it.offset_in_bytes == 148, "FL_POPUP_.entry_font_style has unexpected offset % instead of 148", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.entry_font_style has unexpected size % instead of 4", it.type.runtime_size);
                case "entry_font_size";
                    assert(it.offset_in_bytes == 152, "FL_POPUP_.entry_font_size has unexpected offset % instead of 152", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.entry_font_size has unexpected size % instead of 4", it.type.runtime_size);
                case "event_mask";
                    assert(it.offset_in_bytes == 160, "FL_POPUP_.event_mask has unexpected offset % instead of 160", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.event_mask has unexpected size % instead of 8", it.type.runtime_size);
                case "bw";
                    assert(it.offset_in_bytes == 168, "FL_POPUP_.bw has unexpected offset % instead of 168", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.bw has unexpected size % instead of 4", it.type.runtime_size);
                case "bg_color";
                    assert(it.offset_in_bytes == 176, "FL_POPUP_.bg_color has unexpected offset % instead of 176", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.bg_color has unexpected size % instead of 8", it.type.runtime_size);
                case "on_color";
                    assert(it.offset_in_bytes == 184, "FL_POPUP_.on_color has unexpected offset % instead of 184", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.on_color has unexpected size % instead of 8", it.type.runtime_size);
                case "title_color";
                    assert(it.offset_in_bytes == 192, "FL_POPUP_.title_color has unexpected offset % instead of 192", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.title_color has unexpected size % instead of 8", it.type.runtime_size);
                case "text_color";
                    assert(it.offset_in_bytes == 200, "FL_POPUP_.text_color has unexpected offset % instead of 200", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.text_color has unexpected size % instead of 8", it.type.runtime_size);
                case "text_on_color";
                    assert(it.offset_in_bytes == 208, "FL_POPUP_.text_on_color has unexpected offset % instead of 208", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.text_on_color has unexpected size % instead of 8", it.type.runtime_size);
                case "text_off_color";
                    assert(it.offset_in_bytes == 216, "FL_POPUP_.text_off_color has unexpected offset % instead of 216", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.text_off_color has unexpected size % instead of 8", it.type.runtime_size);
                case "radio_color";
                    assert(it.offset_in_bytes == 224, "FL_POPUP_.radio_color has unexpected offset % instead of 224", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_.radio_color has unexpected size % instead of 8", it.type.runtime_size);
                case "policy";
                    assert(it.offset_in_bytes == 232, "FL_POPUP_.policy has unexpected offset % instead of 232", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.policy has unexpected size % instead of 4", it.type.runtime_size);
                case "need_recalc";
                    assert(it.offset_in_bytes == 236, "FL_POPUP_.need_recalc has unexpected offset % instead of 236", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_.need_recalc has unexpected size % instead of 4", it.type.runtime_size);
                case "ret";
                    assert(it.offset_in_bytes == 240, "FL_POPUP_.ret has unexpected offset % instead of 240", it.offset_in_bytes);
                    assert(it.type.runtime_size == 56, "FL_POPUP_.ret has unexpected size % instead of 56", it.type.runtime_size);
            }
        }
        assert(size_of(FL_POPUP_) == 296, "FL_POPUP_ has size % instead of 296", size_of(FL_POPUP_));
    }

    {
        info := type_info(FL_POPUP_ENTRY_);
        for info.members {
            if it.name == {
                case "prev";
                    assert(it.offset_in_bytes == 0, "FL_POPUP_ENTRY_.prev has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.prev has unexpected size % instead of 8", it.type.runtime_size);
                case "next";
                    assert(it.offset_in_bytes == 8, "FL_POPUP_ENTRY_.next has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.next has unexpected size % instead of 8", it.type.runtime_size);
                case "popup";
                    assert(it.offset_in_bytes == 16, "FL_POPUP_ENTRY_.popup has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.popup has unexpected size % instead of 8", it.type.runtime_size);
                case "is_act";
                    assert(it.offset_in_bytes == 24, "FL_POPUP_ENTRY_.is_act has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.is_act has unexpected size % instead of 4", it.type.runtime_size);
                case "text";
                    assert(it.offset_in_bytes == 32, "FL_POPUP_ENTRY_.text has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.text has unexpected size % instead of 8", it.type.runtime_size);
                case "label";
                    assert(it.offset_in_bytes == 40, "FL_POPUP_ENTRY_.label has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.label has unexpected size % instead of 8", it.type.runtime_size);
                case "accel";
                    assert(it.offset_in_bytes == 48, "FL_POPUP_ENTRY_.accel has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.accel has unexpected size % instead of 8", it.type.runtime_size);
                case "val";
                    assert(it.offset_in_bytes == 56, "FL_POPUP_ENTRY_.val has unexpected offset % instead of 56", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.val has unexpected size % instead of 8", it.type.runtime_size);
                case "user_data";
                    assert(it.offset_in_bytes == 64, "FL_POPUP_ENTRY_.user_data has unexpected offset % instead of 64", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.user_data has unexpected size % instead of 8", it.type.runtime_size);
                case "type";
                    assert(it.offset_in_bytes == 72, "FL_POPUP_ENTRY_.type has unexpected offset % instead of 72", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.type has unexpected size % instead of 4", it.type.runtime_size);
                case "state";
                    assert(it.offset_in_bytes == 76, "FL_POPUP_ENTRY_.state has unexpected offset % instead of 76", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.state has unexpected size % instead of 4", it.type.runtime_size);
                case "group";
                    assert(it.offset_in_bytes == 80, "FL_POPUP_ENTRY_.group has unexpected offset % instead of 80", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.group has unexpected size % instead of 4", it.type.runtime_size);
                case "sub";
                    assert(it.offset_in_bytes == 88, "FL_POPUP_ENTRY_.sub has unexpected offset % instead of 88", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.sub has unexpected size % instead of 8", it.type.runtime_size);
                case "shortcut";
                    assert(it.offset_in_bytes == 96, "FL_POPUP_ENTRY_.shortcut has unexpected offset % instead of 96", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.shortcut has unexpected size % instead of 8", it.type.runtime_size);
                case "ulpos";
                    assert(it.offset_in_bytes == 104, "FL_POPUP_ENTRY_.ulpos has unexpected offset % instead of 104", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.ulpos has unexpected size % instead of 4", it.type.runtime_size);
                case "callback";
                    assert(it.offset_in_bytes == 112, "FL_POPUP_ENTRY_.callback has unexpected offset % instead of 112", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.callback has unexpected size % instead of 8", it.type.runtime_size);
                case "enter_callback";
                    assert(it.offset_in_bytes == 120, "FL_POPUP_ENTRY_.enter_callback has unexpected offset % instead of 120", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.enter_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "leave_callback";
                    assert(it.offset_in_bytes == 128, "FL_POPUP_ENTRY_.leave_callback has unexpected offset % instead of 128", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ENTRY_.leave_callback has unexpected size % instead of 8", it.type.runtime_size);
                case "x";
                    assert(it.offset_in_bytes == 136, "FL_POPUP_ENTRY_.x has unexpected offset % instead of 136", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.x has unexpected size % instead of 4", it.type.runtime_size);
                case "y";
                    assert(it.offset_in_bytes == 140, "FL_POPUP_ENTRY_.y has unexpected offset % instead of 140", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.y has unexpected size % instead of 4", it.type.runtime_size);
                case "w";
                    assert(it.offset_in_bytes == 144, "FL_POPUP_ENTRY_.w has unexpected offset % instead of 144", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.w has unexpected size % instead of 4", it.type.runtime_size);
                case "h";
                    assert(it.offset_in_bytes == 148, "FL_POPUP_ENTRY_.h has unexpected offset % instead of 148", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.h has unexpected size % instead of 4", it.type.runtime_size);
                case "box_x";
                    assert(it.offset_in_bytes == 152, "FL_POPUP_ENTRY_.box_x has unexpected offset % instead of 152", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.box_x has unexpected size % instead of 4", it.type.runtime_size);
                case "box_y";
                    assert(it.offset_in_bytes == 156, "FL_POPUP_ENTRY_.box_y has unexpected offset % instead of 156", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.box_y has unexpected size % instead of 4", it.type.runtime_size);
                case "box_w";
                    assert(it.offset_in_bytes == 160, "FL_POPUP_ENTRY_.box_w has unexpected offset % instead of 160", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.box_w has unexpected size % instead of 4", it.type.runtime_size);
                case "box_h";
                    assert(it.offset_in_bytes == 164, "FL_POPUP_ENTRY_.box_h has unexpected offset % instead of 164", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.box_h has unexpected size % instead of 4", it.type.runtime_size);
                case "sl_h";
                    assert(it.offset_in_bytes == 168, "FL_POPUP_ENTRY_.sl_h has unexpected offset % instead of 168", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.sl_h has unexpected size % instead of 4", it.type.runtime_size);
                case "ul_x";
                    assert(it.offset_in_bytes == 172, "FL_POPUP_ENTRY_.ul_x has unexpected offset % instead of 172", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.ul_x has unexpected size % instead of 4", it.type.runtime_size);
                case "ul_y";
                    assert(it.offset_in_bytes == 176, "FL_POPUP_ENTRY_.ul_y has unexpected offset % instead of 176", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.ul_y has unexpected size % instead of 4", it.type.runtime_size);
                case "ul_w";
                    assert(it.offset_in_bytes == 180, "FL_POPUP_ENTRY_.ul_w has unexpected offset % instead of 180", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.ul_w has unexpected size % instead of 4", it.type.runtime_size);
                case "ul_h";
                    assert(it.offset_in_bytes == 184, "FL_POPUP_ENTRY_.ul_h has unexpected offset % instead of 184", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ENTRY_.ul_h has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(FL_POPUP_ENTRY_) == 192, "FL_POPUP_ENTRY_ has size % instead of 192", size_of(FL_POPUP_ENTRY_));
    }

    {
        info := type_info(FL_POPUP_ITEM);
        for info.members {
            if it.name == {
                case "text";
                    assert(it.offset_in_bytes == 0, "FL_POPUP_ITEM.text has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ITEM.text has unexpected size % instead of 8", it.type.runtime_size);
                case "callback";
                    assert(it.offset_in_bytes == 8, "FL_POPUP_ITEM.callback has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ITEM.callback has unexpected size % instead of 8", it.type.runtime_size);
                case "shortcut";
                    assert(it.offset_in_bytes == 16, "FL_POPUP_ITEM.shortcut has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_POPUP_ITEM.shortcut has unexpected size % instead of 8", it.type.runtime_size);
                case "type";
                    assert(it.offset_in_bytes == 24, "FL_POPUP_ITEM.type has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ITEM.type has unexpected size % instead of 4", it.type.runtime_size);
                case "state";
                    assert(it.offset_in_bytes == 28, "FL_POPUP_ITEM.state has unexpected offset % instead of 28", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_POPUP_ITEM.state has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(FL_POPUP_ITEM) == 32, "FL_POPUP_ITEM has size % instead of 32", size_of(FL_POPUP_ITEM));
    }

    {
        info := type_info(FL_BUTTON_SPEC);
        for info.members {
            if it.name == {
                case "pixmap";
                    assert(it.offset_in_bytes == 0, "FL_BUTTON_SPEC.pixmap has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_BUTTON_SPEC.pixmap has unexpected size % instead of 8", it.type.runtime_size);
                case "mask";
                    assert(it.offset_in_bytes == 8, "FL_BUTTON_SPEC.mask has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_BUTTON_SPEC.mask has unexpected size % instead of 8", it.type.runtime_size);
                case "bits_w";
                    assert(it.offset_in_bytes == 16, "FL_BUTTON_SPEC.bits_w has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_BUTTON_SPEC.bits_w has unexpected size % instead of 4", it.type.runtime_size);
                case "bits_h";
                    assert(it.offset_in_bytes == 20, "FL_BUTTON_SPEC.bits_h has unexpected offset % instead of 20", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_BUTTON_SPEC.bits_h has unexpected size % instead of 4", it.type.runtime_size);
                case "val";
                    assert(it.offset_in_bytes == 24, "FL_BUTTON_SPEC.val has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_BUTTON_SPEC.val has unexpected size % instead of 4", it.type.runtime_size);
                case "mousebut";
                    assert(it.offset_in_bytes == 28, "FL_BUTTON_SPEC.mousebut has unexpected offset % instead of 28", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_BUTTON_SPEC.mousebut has unexpected size % instead of 4", it.type.runtime_size);
                case "timdel";
                    assert(it.offset_in_bytes == 32, "FL_BUTTON_SPEC.timdel has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_BUTTON_SPEC.timdel has unexpected size % instead of 4", it.type.runtime_size);
                case "event";
                    assert(it.offset_in_bytes == 36, "FL_BUTTON_SPEC.event has unexpected offset % instead of 36", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_BUTTON_SPEC.event has unexpected size % instead of 4", it.type.runtime_size);
                case "is_pushed";
                    assert(it.offset_in_bytes == 40, "FL_BUTTON_SPEC.is_pushed has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_BUTTON_SPEC.is_pushed has unexpected size % instead of 4", it.type.runtime_size);
                case "react_to";
                    assert(it.offset_in_bytes == 44, "FL_BUTTON_SPEC.react_to has unexpected offset % instead of 44", it.offset_in_bytes);
                    assert(it.type.runtime_size == 20, "FL_BUTTON_SPEC.react_to has unexpected size % instead of 20", it.type.runtime_size);
                case "cspecl";
                    assert(it.offset_in_bytes == 64, "FL_BUTTON_SPEC.cspecl has unexpected offset % instead of 64", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_BUTTON_SPEC.cspecl has unexpected size % instead of 8", it.type.runtime_size);
                case "cspecv";
                    assert(it.offset_in_bytes == 72, "FL_BUTTON_SPEC.cspecv has unexpected offset % instead of 72", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_BUTTON_SPEC.cspecv has unexpected size % instead of 8", it.type.runtime_size);
                case "filename";
                    assert(it.offset_in_bytes == 80, "FL_BUTTON_SPEC.filename has unexpected offset % instead of 80", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_BUTTON_SPEC.filename has unexpected size % instead of 8", it.type.runtime_size);
                case "focus_pixmap";
                    assert(it.offset_in_bytes == 88, "FL_BUTTON_SPEC.focus_pixmap has unexpected offset % instead of 88", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_BUTTON_SPEC.focus_pixmap has unexpected size % instead of 8", it.type.runtime_size);
                case "focus_mask";
                    assert(it.offset_in_bytes == 96, "FL_BUTTON_SPEC.focus_mask has unexpected offset % instead of 96", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_BUTTON_SPEC.focus_mask has unexpected size % instead of 8", it.type.runtime_size);
                case "focus_filename";
                    assert(it.offset_in_bytes == 104, "FL_BUTTON_SPEC.focus_filename has unexpected offset % instead of 104", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_BUTTON_SPEC.focus_filename has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(FL_BUTTON_SPEC) == 112, "FL_BUTTON_SPEC has size % instead of 112", size_of(FL_BUTTON_SPEC));
    }

    {
        info := type_info(FL_Dirlist);
        for info.members {
            if it.name == {
                case "name";
                    assert(it.offset_in_bytes == 0, "FL_Dirlist.name has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_Dirlist.name has unexpected size % instead of 8", it.type.runtime_size);
                case "type";
                    assert(it.offset_in_bytes == 8, "FL_Dirlist.type has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FL_Dirlist.type has unexpected size % instead of 4", it.type.runtime_size);
                case "dl_mtime";
                    assert(it.offset_in_bytes == 16, "FL_Dirlist.dl_mtime has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_Dirlist.dl_mtime has unexpected size % instead of 8", it.type.runtime_size);
                case "dl_size";
                    assert(it.offset_in_bytes == 24, "FL_Dirlist.dl_size has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_Dirlist.dl_size has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(FL_Dirlist) == 32, "FL_Dirlist has size % instead of 32", size_of(FL_Dirlist));
    }

    {
        info := type_info(FLPS_CONTROL);
        for info.members {
            if it.name == {
                case "ps_color";
                    assert(it.offset_in_bytes == 0, "FLPS_CONTROL.ps_color has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.ps_color has unexpected size % instead of 4", it.type.runtime_size);
                case "orientation";
                    assert(it.offset_in_bytes == 4, "FLPS_CONTROL.orientation has unexpected offset % instead of 4", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.orientation has unexpected size % instead of 4", it.type.runtime_size);
                case "auto_fit";
                    assert(it.offset_in_bytes == 8, "FLPS_CONTROL.auto_fit has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.auto_fit has unexpected size % instead of 4", it.type.runtime_size);
                case "drawbox";
                    assert(it.offset_in_bytes == 12, "FLPS_CONTROL.drawbox has unexpected offset % instead of 12", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.drawbox has unexpected size % instead of 4", it.type.runtime_size);
                case "eps";
                    assert(it.offset_in_bytes == 16, "FLPS_CONTROL.eps has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.eps has unexpected size % instead of 4", it.type.runtime_size);
                case "xdpi";
                    assert(it.offset_in_bytes == 20, "FLPS_CONTROL.xdpi has unexpected offset % instead of 20", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.xdpi has unexpected size % instead of 4", it.type.runtime_size);
                case "ydpi";
                    assert(it.offset_in_bytes == 24, "FLPS_CONTROL.ydpi has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.ydpi has unexpected size % instead of 4", it.type.runtime_size);
                case "paper_w";
                    assert(it.offset_in_bytes == 28, "FLPS_CONTROL.paper_w has unexpected offset % instead of 28", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.paper_w has unexpected size % instead of 4", it.type.runtime_size);
                case "paper_h";
                    assert(it.offset_in_bytes == 32, "FLPS_CONTROL.paper_h has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.paper_h has unexpected size % instead of 4", it.type.runtime_size);
                case "gamma";
                    assert(it.offset_in_bytes == 36, "FLPS_CONTROL.gamma has unexpected offset % instead of 36", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.gamma has unexpected size % instead of 4", it.type.runtime_size);
                case "tmpdir";
                    assert(it.offset_in_bytes == 40, "FLPS_CONTROL.tmpdir has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FLPS_CONTROL.tmpdir has unexpected size % instead of 8", it.type.runtime_size);
                case "printer_dpi";
                    assert(it.offset_in_bytes == 48, "FLPS_CONTROL.printer_dpi has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.printer_dpi has unexpected size % instead of 4", it.type.runtime_size);
                case "hm";
                    assert(it.offset_in_bytes == 52, "FLPS_CONTROL.hm has unexpected offset % instead of 52", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.hm has unexpected size % instead of 4", it.type.runtime_size);
                case "vm";
                    assert(it.offset_in_bytes == 56, "FLPS_CONTROL.vm has unexpected offset % instead of 56", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.vm has unexpected size % instead of 4", it.type.runtime_size);
                case "xscale";
                    assert(it.offset_in_bytes == 60, "FLPS_CONTROL.xscale has unexpected offset % instead of 60", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.xscale has unexpected size % instead of 4", it.type.runtime_size);
                case "yscale";
                    assert(it.offset_in_bytes == 64, "FLPS_CONTROL.yscale has unexpected offset % instead of 64", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.yscale has unexpected size % instead of 4", it.type.runtime_size);
                case "scale_text";
                    assert(it.offset_in_bytes == 68, "FLPS_CONTROL.scale_text has unexpected offset % instead of 68", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.scale_text has unexpected size % instead of 4", it.type.runtime_size);
                case "first_page_only";
                    assert(it.offset_in_bytes == 72, "FLPS_CONTROL.first_page_only has unexpected offset % instead of 72", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.first_page_only has unexpected size % instead of 4", it.type.runtime_size);
                case "clip";
                    assert(it.offset_in_bytes == 76, "FLPS_CONTROL.clip has unexpected offset % instead of 76", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "FLPS_CONTROL.clip has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(FLPS_CONTROL) == 80, "FLPS_CONTROL has size % instead of 80", size_of(FLPS_CONTROL));
    }

    {
        info := type_info(FD_CMDLOG);
        for info.members {
            if it.name == {
                case "form";
                    assert(it.offset_in_bytes == 0, "FD_CMDLOG.form has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_CMDLOG.form has unexpected size % instead of 8", it.type.runtime_size);
                case "vdata";
                    assert(it.offset_in_bytes == 8, "FD_CMDLOG.vdata has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_CMDLOG.vdata has unexpected size % instead of 8", it.type.runtime_size);
                case "cdata";
                    assert(it.offset_in_bytes == 16, "FD_CMDLOG.cdata has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_CMDLOG.cdata has unexpected size % instead of 8", it.type.runtime_size);
                case "ldata";
                    assert(it.offset_in_bytes == 24, "FD_CMDLOG.ldata has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_CMDLOG.ldata has unexpected size % instead of 8", it.type.runtime_size);
                case "browser";
                    assert(it.offset_in_bytes == 32, "FD_CMDLOG.browser has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_CMDLOG.browser has unexpected size % instead of 8", it.type.runtime_size);
                case "close_browser";
                    assert(it.offset_in_bytes == 40, "FD_CMDLOG.close_browser has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_CMDLOG.close_browser has unexpected size % instead of 8", it.type.runtime_size);
                case "clear_browser";
                    assert(it.offset_in_bytes == 48, "FD_CMDLOG.clear_browser has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_CMDLOG.clear_browser has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(FD_CMDLOG) == 56, "FD_CMDLOG has size % instead of 56", size_of(FD_CMDLOG));
    }

    {
        info := type_info(FD_FSELECTOR);
        for info.members {
            if it.name == {
                case "fselect";
                    assert(it.offset_in_bytes == 0, "FD_FSELECTOR.fselect has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.fselect has unexpected size % instead of 8", it.type.runtime_size);
                case "vdata";
                    assert(it.offset_in_bytes == 8, "FD_FSELECTOR.vdata has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.vdata has unexpected size % instead of 8", it.type.runtime_size);
                case "cdata";
                    assert(it.offset_in_bytes == 16, "FD_FSELECTOR.cdata has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.cdata has unexpected size % instead of 8", it.type.runtime_size);
                case "ldata";
                    assert(it.offset_in_bytes == 24, "FD_FSELECTOR.ldata has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.ldata has unexpected size % instead of 8", it.type.runtime_size);
                case "browser";
                    assert(it.offset_in_bytes == 32, "FD_FSELECTOR.browser has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.browser has unexpected size % instead of 8", it.type.runtime_size);
                case "input";
                    assert(it.offset_in_bytes == 40, "FD_FSELECTOR.input has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.input has unexpected size % instead of 8", it.type.runtime_size);
                case "prompt";
                    assert(it.offset_in_bytes == 48, "FD_FSELECTOR.prompt has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.prompt has unexpected size % instead of 8", it.type.runtime_size);
                case "resbutt";
                    assert(it.offset_in_bytes == 56, "FD_FSELECTOR.resbutt has unexpected offset % instead of 56", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.resbutt has unexpected size % instead of 8", it.type.runtime_size);
                case "patbutt";
                    assert(it.offset_in_bytes == 64, "FD_FSELECTOR.patbutt has unexpected offset % instead of 64", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.patbutt has unexpected size % instead of 8", it.type.runtime_size);
                case "dirbutt";
                    assert(it.offset_in_bytes == 72, "FD_FSELECTOR.dirbutt has unexpected offset % instead of 72", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.dirbutt has unexpected size % instead of 8", it.type.runtime_size);
                case "cancel";
                    assert(it.offset_in_bytes == 80, "FD_FSELECTOR.cancel has unexpected offset % instead of 80", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.cancel has unexpected size % instead of 8", it.type.runtime_size);
                case "ready";
                    assert(it.offset_in_bytes == 88, "FD_FSELECTOR.ready has unexpected offset % instead of 88", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.ready has unexpected size % instead of 8", it.type.runtime_size);
                case "dirlabel";
                    assert(it.offset_in_bytes == 96, "FD_FSELECTOR.dirlabel has unexpected offset % instead of 96", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.dirlabel has unexpected size % instead of 8", it.type.runtime_size);
                case "patlabel";
                    assert(it.offset_in_bytes == 104, "FD_FSELECTOR.patlabel has unexpected offset % instead of 104", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FD_FSELECTOR.patlabel has unexpected size % instead of 8", it.type.runtime_size);
                case "appbutt";
                    assert(it.offset_in_bytes == 112, "FD_FSELECTOR.appbutt has unexpected offset % instead of 112", it.offset_in_bytes);
                    assert(it.type.runtime_size == 24, "FD_FSELECTOR.appbutt has unexpected size % instead of 24", it.type.runtime_size);
            }
        }
        assert(size_of(FD_FSELECTOR) == 136, "FD_FSELECTOR has size % instead of 136", size_of(FD_FSELECTOR));
    }

    {
        info := type_info(FL_EditKeymap);
        for info.members {
            if it.name == {
                case "del_prev_char";
                    assert(it.offset_in_bytes == 0, "FL_EditKeymap.del_prev_char has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.del_prev_char has unexpected size % instead of 8", it.type.runtime_size);
                case "del_next_char";
                    assert(it.offset_in_bytes == 8, "FL_EditKeymap.del_next_char has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.del_next_char has unexpected size % instead of 8", it.type.runtime_size);
                case "del_prev_word";
                    assert(it.offset_in_bytes == 16, "FL_EditKeymap.del_prev_word has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.del_prev_word has unexpected size % instead of 8", it.type.runtime_size);
                case "del_next_word";
                    assert(it.offset_in_bytes == 24, "FL_EditKeymap.del_next_word has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.del_next_word has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_prev_line";
                    assert(it.offset_in_bytes == 32, "FL_EditKeymap.moveto_prev_line has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_prev_line has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_next_line";
                    assert(it.offset_in_bytes == 40, "FL_EditKeymap.moveto_next_line has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_next_line has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_prev_char";
                    assert(it.offset_in_bytes == 48, "FL_EditKeymap.moveto_prev_char has unexpected offset % instead of 48", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_prev_char has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_next_char";
                    assert(it.offset_in_bytes == 56, "FL_EditKeymap.moveto_next_char has unexpected offset % instead of 56", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_next_char has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_prev_word";
                    assert(it.offset_in_bytes == 64, "FL_EditKeymap.moveto_prev_word has unexpected offset % instead of 64", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_prev_word has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_next_word";
                    assert(it.offset_in_bytes == 72, "FL_EditKeymap.moveto_next_word has unexpected offset % instead of 72", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_next_word has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_prev_page";
                    assert(it.offset_in_bytes == 80, "FL_EditKeymap.moveto_prev_page has unexpected offset % instead of 80", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_prev_page has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_next_page";
                    assert(it.offset_in_bytes == 88, "FL_EditKeymap.moveto_next_page has unexpected offset % instead of 88", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_next_page has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_bol";
                    assert(it.offset_in_bytes == 96, "FL_EditKeymap.moveto_bol has unexpected offset % instead of 96", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_bol has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_eol";
                    assert(it.offset_in_bytes == 104, "FL_EditKeymap.moveto_eol has unexpected offset % instead of 104", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_eol has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_bof";
                    assert(it.offset_in_bytes == 112, "FL_EditKeymap.moveto_bof has unexpected offset % instead of 112", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_bof has unexpected size % instead of 8", it.type.runtime_size);
                case "moveto_eof";
                    assert(it.offset_in_bytes == 120, "FL_EditKeymap.moveto_eof has unexpected offset % instead of 120", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.moveto_eof has unexpected size % instead of 8", it.type.runtime_size);
                case "transpose";
                    assert(it.offset_in_bytes == 128, "FL_EditKeymap.transpose has unexpected offset % instead of 128", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.transpose has unexpected size % instead of 8", it.type.runtime_size);
                case "paste";
                    assert(it.offset_in_bytes == 136, "FL_EditKeymap.paste has unexpected offset % instead of 136", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.paste has unexpected size % instead of 8", it.type.runtime_size);
                case "backspace";
                    assert(it.offset_in_bytes == 144, "FL_EditKeymap.backspace has unexpected offset % instead of 144", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.backspace has unexpected size % instead of 8", it.type.runtime_size);
                case "del_to_bol";
                    assert(it.offset_in_bytes == 152, "FL_EditKeymap.del_to_bol has unexpected offset % instead of 152", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.del_to_bol has unexpected size % instead of 8", it.type.runtime_size);
                case "del_to_eol";
                    assert(it.offset_in_bytes == 160, "FL_EditKeymap.del_to_eol has unexpected offset % instead of 160", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.del_to_eol has unexpected size % instead of 8", it.type.runtime_size);
                case "clear_field";
                    assert(it.offset_in_bytes == 168, "FL_EditKeymap.clear_field has unexpected offset % instead of 168", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.clear_field has unexpected size % instead of 8", it.type.runtime_size);
                case "del_to_eos";
                    assert(it.offset_in_bytes == 176, "FL_EditKeymap.del_to_eos has unexpected offset % instead of 176", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "FL_EditKeymap.del_to_eos has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(FL_EditKeymap) == 184, "FL_EditKeymap has size % instead of 184", size_of(FL_EditKeymap));
    }
}

