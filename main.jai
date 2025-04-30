#import "Basic";
#import "Socket";
#import "POSIX";
#import "Thread";
#import "System";
#import "String";
forms :: #import "XForms";

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
chat_area:    *forms.Object;
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

make_chat_form :: () {
    chat_form = forms.begin_form(.UP_BOX, WINDOW_WIDTH, WINDOW_HEIGHT);
    defer forms.end_form();

    chat_area = forms.add_input(.MULTILINE_INPUT, 0,  0,  WINDOW_WIDTH,  WINDOW_HEIGHT - 30);
    // forms.fl_activate_object(chat_area);
    // forms.fl_deactivate_object(chat_area);
    forms.set_gravity(chat_area, .NorthWest, .SouthEast);
    forms.fl_set_input_scroll(chat_area, 1);

    message_box = forms.add_input(.NORMAL_INPUT, 0,  WINDOW_HEIGHT - 30,  WINDOW_WIDTH - 100,  30);
    forms.set_gravity(message_box, .SouthWest, .South);
    forms.set_callback(message_box, message_box_callback);
    forms.fl_set_focus_object(chat_form, message_box);

    send_message_button := forms.add_button(.NORMAL_BUTTON, WINDOW_WIDTH - 100, WINDOW_HEIGHT - 30, 100, 30, "Send");
    forms.set_gravity(send_message_button, .South, .SouthEast);
    forms.set_callback(send_message_button, send_message_callback);

    reset_temporary_storage();
}

message_box_callback  :: (object: *forms.Object, data: s64) { send_message(); }
send_message_callback :: (object: *forms.Object, data: s64) { send_message(); }

send_message :: () {
    message := forms.get_input(message_box);
    write(socket_file_descriptor, message.data, xx message.count);

    lock(*ui_mutex);
    defer unlock(*ui_mutex);

    append(*messages_builder, "me: ");
    append(*messages_builder, message);
    append(*messages_builder, "\n");
    forms.set_input(message_box, "");

    forms.set_input(chat_area, builder_to_string(*messages_builder, do_reset=false,, temp));

    forms.fl_set_focus_object(chat_form, message_box);

    reset_temporary_storage();
}

message_listener :: (thread: *Thread) -> s64 {
    while true {
        buffer: [1024]u8;
        amount_read := read(socket_file_descriptor, buffer.data, buffer.count);
        assert(amount_read != -1 && amount_read != 0); // TODO: Deal with disconnects

        lock(*ui_mutex);
        defer unlock(*ui_mutex);

        message: string;
        message.data  = buffer.data;
        message.count = amount_read;

        append(*messages_builder, "other: ");
        append(*messages_builder, trim(message));
        append(*messages_builder, "\n");

        new_text := builder_to_string(*messages_builder, do_reset=false,, temp);
        forms.set_input(chat_area, new_text);

        count: s32 = 0;
        for new_text
            if it == #char "\n" then count += 1;

        forms.fl_set_input_cursorpos(chat_area, 0, count + 1);

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

    if connect(socket_file_descriptor, xx *server_address, size_of(sockaddr_in)) == -1 {
        log("connection with the server failed: %", get_error_string(errno()));
        return;
    }

    init(*ui_mutex);

    thread_init(*read_message_thread, message_listener);
    thread_start(*read_message_thread);

    log("success!");
    forms.hide_form(welcome_form);
    forms.show_form(chat_form, .FREE, .FULLBORDER, "XChatger");
}

b: *forms.Form;
browser: *forms.Object;

main :: () {
    forms.initialize();

    make_chat_form();
    make_welcome_form();

    // forms.show_form(welcome_form, .FREE, .FULLBORDER, "XChatger");
    channels := forms.begin_form(.FLAT_BOX, 200, 500);
        y: s32 = 0;
        forms.add_button(.NORMAL_BUTTON, 0, y, 200, 30, "Channel 1"); y += 30;
        forms.add_button(.NORMAL_BUTTON, 0, y, 200, 30, "Channel 2"); y += 30;
        forms.add_button(.NORMAL_BUTTON, 0, y, 200, 30, "Channel 3"); y += 30;
        forms.add_button(.NORMAL_BUTTON, 0, y, 200, 30, "Channel 4"); y += 30;
        forms.add_button(.NORMAL_BUTTON, 0, y, 200, 30, "Channel 5"); y += 30;
    forms.end_form();

    b = forms.begin_form(.UP_BOX, WINDOW_WIDTH, WINDOW_HEIGHT);
        side_bar :: 200;

        folder := forms.fl_add_tabfolder(xx forms.FL_20.TOP_TABFOLDER, 0, 0, side_bar, 500, "Test folder");
        forms.set_gravity(folder, .West, .West);

        // thing := forms.fl_create_button(0, 0, 0, 50, 30, "Hello");
        forms.fl_addto_tabfolder(folder, "Channels", channels);

        browser = forms.fl_add_formbrowser(0, side_bar, 0, 800 - side_bar, 500, "Test label");
        forms.set_gravity(browser, .West, .East);

        button := forms.add_button(.NORMAL_BUTTON, 0, 500, 800, 100, "click me!");
        forms.set_callback(button, (object: *forms.Object, data: s64) {
            log("Clicked!");

            sub_form := forms.begin_form(.FLAT_BOX, WINDOW_WIDTH, 50);
                forms.add_button(.NORMAL_BUTTON, 0, 0, 100, 20, "wooptiedoo!");
            forms.end_form();


            forms.fl_addto_formbrowser(browser, sub_form);
        });

    forms.end_form();

    forms.show_form(b, .FREE, .FULLBORDER, "XChatger");

    while forms.do_forms() {
    }
}
