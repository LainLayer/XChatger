#import "Basic";
#import "Socket";
#import "POSIX";
#import "Thread";
#import "System";
#import "String";
forms :: #import "XForms";

#import "Protocol";

WINDOW_WIDTH  :: 800;
WINDOW_HEIGHT :: 600;

Rectangle :: struct {
    x: s32;
    y: s32;
    width: s32;
    height: s32;
}

operator - :: inline (using rectangle: Rectangle, number: s32) -> Rectangle {
    return Rectangle.{
        x      = x      + number,
        y      = y      + number,
        width  = width  - number*2,
        height = height - number*2
    };
}

welcome_form: *forms.Form;
chat_form:    *forms.Form;
message_box:  *forms.Object;
// chat_area:    *forms.Object;

message_browser: *forms.Object;

socket_file_descriptor: s32;

messages_builder: String_Builder;

ui_mutex: Mutex;
read_message_thread: Thread;

make_welcome_form :: () {
    welcome_form = forms.begin_form(.UP_BOX, WINDOW_WIDTH, WINDOW_HEIGHT);
    defer forms.end_form();

    image := forms.add_bitmap(WINDOW_WIDTH - 256 - 15, WINDOW_HEIGHT - 256 - 15, 256, 256);
    forms.set_bitmap_file(image, "./Laptopger.xbm");
    forms.set_gravity(image, .SouthEast, .SouthEast);

    r := Rectangle.{0, 0, WINDOW_WIDTH / 2, 50};
    r.x     += 30;
    r.width -= 30;

    left    := r - 10;
    right   := r;
    right.x += WINDOW_WIDTH / 2;
    right   -= 10;
    host := forms.add_input(.NORMAL_INPUT, left.x,  left.y,  left.width,  left.height,  "host");
    port := forms.add_input(.NORMAL_INPUT, right.x, right.y, right.width, right.height, "port");
    forms.set_gravity(host, .NorthWest, .North);
    forms.set_gravity(port, .North, .NorthEast);

    forms.set_input(host, "0.0.0.0");
    forms.set_input(port, "4348");

    connect_button := forms.add_button(.NORMAL_BUTTON, 10, r.height + 10, WINDOW_WIDTH - 20, 30, "Conenct");
    forms.set_gravity(connect_button, .NorthWest, .NorthEast);

    forms.set_callback(connect_button, connect_button_callback);

    footer_text := forms.add_text(10, WINDOW_HEIGHT - 40, 300, 18*2, "XChatger - (c) LainLayer 2025\ngithub.com/LainLayer - http://solarium.technology");
    forms.set_gravity(footer_text, .SouthWest, .SouthWest);

    reset_temporary_storage();
}

make_channels_form :: () -> *forms.Form {
    channels := forms.begin_form(.FLAT_BOX, 200, 500);
        y: s32 = 0;
        forms.add_button(.NORMAL_BUTTON, 0, y, 200, 30, "Channel 1"); y += 30;
        forms.add_button(.NORMAL_BUTTON, 0, y, 200, 30, "Channel 2"); y += 30;
        forms.add_button(.NORMAL_BUTTON, 0, y, 200, 30, "Channel 3"); y += 30;
        forms.add_button(.NORMAL_BUTTON, 0, y, 200, 30, "Channel 4"); y += 30;
        forms.add_button(.NORMAL_BUTTON, 0, y, 200, 30, "Channel 5"); y += 30;
    forms.end_form();

    return channels;
}

make_chat_form :: () {
    channels := make_channels_form();

    chat_form = forms.begin_form(.UP_BOX, WINDOW_WIDTH, WINDOW_HEIGHT);
    defer forms.end_form();

    side_bar :: 200;


    folder := forms.add_tab_folder(.TOP_TABFOLDER, 0, 0, side_bar, WINDOW_HEIGHT, "Test folder");
    forms.set_gravity(folder, .West, .West);

    forms.add_form_as_tab(folder, "Channels", channels);

    message_browser = forms.fl_add_formbrowser(0, side_bar, 0, 800 - side_bar, 570, "Test label");
    forms.set_gravity(message_browser, .West, .East);
    // forms.fl_deactivate_object(message_browser);

    // TODO: Fix issue here current if the mouse is anywhere on `message_browser` then its not possible
    // to type inside this message box. Maybe this should be in its own form and somehow added to the
    // bottom of `message_brwoser`?
    message_box = forms.add_input(.NORMAL_INPUT, side_bar,  WINDOW_HEIGHT - 30,  WINDOW_WIDTH - 100 - side_bar,  30);
    forms.set_gravity(message_box, .West, .East);
    forms.set_callback(message_box, message_box_callback);
    // forms.fl_set_focus_object(chat_form, message_box);

    send_message_button := forms.add_button(.NORMAL_BUTTON, WINDOW_WIDTH - 100, WINDOW_HEIGHT - 30, 100, 30, "Send");
    forms.set_gravity(send_message_button, .East, .East);
    forms.set_callback(send_message_button, send_message_callback);

    reset_temporary_storage();
}

message_box_callback  :: (object: *forms.Object, data: s64) { send_message(); }
send_message_callback :: (object: *forms.Object, data: s64) { send_message(); }

send_message :: () {

    message := forms.get_input(message_box);

    if trim(message) == "" then return;

    send_text_message(socket_file_descriptor, message, 1);

    lock(*ui_mutex);
    defer unlock(*ui_mutex);
    forms.fl_addto_formbrowser(message_browser, make_message_form(message));

    forms.set_input(message_box, "");

    reset_temporary_storage();
}

message_listener :: (thread: *Thread) -> s64 {

    heap := context.allocator;

    push_allocator(temp);

    while true {

        for message : get_messages(socket_file_descriptor, heap) {
            if message.type == {
                case .TEXT;
                    text_message := message.as_text_message;

                    lock(*ui_mutex);
                    defer unlock(*ui_mutex);
                    forms.fl_addto_formbrowser(message_browser, make_message_form(text_message.text));
                case;
                    assert(false, "unimplemented");
            }
        }

        reset_temporary_storage();
    }

    return 0;
}

connect_button_callback :: (object: *forms.Object, data: s64) {
    print("connecting!\n");

    socket_file_descriptor = socket(AF_INET, .STREAM, 0);

    if socket_file_descriptor == -1 {
        log("Failed to create socket: %", get_error_string(errno()));
        return;
    }

    server_address: sockaddr_in;
    server_address.sin_family      = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_address.sin_port        = htons(4348);
    // TODO: Get the actual data from the welcome form

    if connect(socket_file_descriptor, xx *server_address, size_of(sockaddr_in)) == -1 {
        log("connection with the server failed: %", get_error_string(errno()));
        return;
    }

    init(*ui_mutex);

    thread_init(*read_message_thread, message_listener);
    thread_start(*read_message_thread);

    send_login_message(socket_file_descriptor, username="cephon", password="MySuperSecurePassword");

    log("success!");
    forms.hide_form(welcome_form);
    forms.show_form(chat_form, .FREE, .FULLBORDER, "XChatger");
}

make_message_form :: (text: string) -> *forms.Form {
    form := forms.begin_form(.FLAT_BOX, WINDOW_WIDTH, 50);
    defer forms.end_form();

    forms.add_button(.NORMAL_BUTTON, 50, 0, 100, 20, "Mr Epic Username");
    pixbutton := forms.fl_add_pixmapbutton(xx forms.FL_BUTTON_TYPE.NORMAL_BUTTON, 0, 0, 50, 50, "test");
    forms.fl_set_pixmapbutton_file(pixbutton, "./Laptopger.xpm");

    // TODO: Wordwrap this
    message_box := forms.add_text(50, 20, 600, 30, text);

    return form;
}

main :: () {

    // context.print_style.struct_printer = printer_with_big_endian;

    forms.initialize();

    make_chat_form();
    make_welcome_form();

    forms.show_form(welcome_form, .FREE, .FULLBORDER, "XChatger");

    while forms.do_forms() {
    }
}
