/*
 *  This file is part of the XForms library package.
 *
 *  XForms is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1, or
 *  (at your option) any later version.
 *
 *  XForms is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.     See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */

/********************** crop here for forms.h **********************/

/**
 * \file goodies.h
 */

#ifndef FL_GOODIES_H
#define FL_GOODIES_H

/***** Resources and misc. goodie routines ******/

#define FLAlertDismissLabel     "flAlert.dismiss.label"
#define FLAlertTitle            "flAlert.title"

#define FLQuestionYesLabel      "flQuestion.yes.label"
#define FLQuestionNoLabel       "flQuestion.no.label"
#define FLQuestionTitle         "flQuestion.title"

#define FLOKLabel               "flInput.ok.label"
#define FLInputClearLabel       "flInput.clear.label"
#define FLInputCancelLabel      "flInput.cancel.label"
#define FLInputTitle            "flInput.title"

#define FLChoiceTitle           "flChoice.title"

FL_EXPORT void fl_set_goodies_font(
        int style,
        int size
        );

/*********** messages and questions **************/

FL_EXPORT void fl_show_message( const char *,
                                const char *,
                                const char * );

FL_EXPORT void fl_show_messages( const char * );

#define fl_show_msg fl_show_messages_f
FL_EXPORT void fl_show_messages_f( const char *,
								   ... );

FL_EXPORT void fl_hide_message( void );

#define fl_hide_msg       fl_hide_message
#define fl_hide_messages  fl_hide_message

FL_EXPORT int fl_show_question( const char *,
                                int );

FL_EXPORT void fl_hide_question( void );

FL_EXPORT void fl_show_alert( const char *,
                              const char *,
                              const char *,
                              int );


#define fl_show_alert2  fl_show_alert_f
FL_EXPORT void fl_show_alert_f( int          c,
								const char * fmt,
                               ... );

FL_EXPORT void fl_hide_alert( void );

FL_EXPORT const char * fl_show_input( const char *,
                                      const char * );

FL_EXPORT void fl_hide_input( void );

FL_EXPORT const char * fl_show_simple_input( const char *,
                                             const char * );

FL_EXPORT int fl_show_colormap( int );

/********* choices *****************/

FL_EXPORT int fl_show_choices( const char *,
                               int,
                               const char *,
                               const char *,
                               const char *,
                               int );

FL_EXPORT int fl_show_choice( const char *,
                              const char *,
                              const char *,
                              int,
                              const char *,
                              const char *,
                              const char *,
                              int );

FL_EXPORT void fl_hide_choice( void );

FL_EXPORT void fl_set_choices_shortcut( const char *,
                                       const char *,
                                       const char * );

#define fl_set_choice_shortcut fl_set_choices_shortcut

/************ one liner ***************/

FL_EXPORT void fl_show_oneliner( const char *,
                                 FL_Coord,
                                 FL_Coord );

FL_EXPORT void fl_hide_oneliner( void );

FL_EXPORT void fl_set_oneliner_font( int,
                                     int );

FL_EXPORT void fl_set_oneliner_color( FL_COLOR,
                                      FL_COLOR );

FL_EXPORT void fl_set_tooltip_font( int,
                                    int );

FL_EXPORT void fl_set_tooltip_color( FL_COLOR,
                                     FL_COLOR );

FL_EXPORT void fl_set_tooltip_boxtype( int );

FL_EXPORT void fl_set_tooltip_lalign( int );

/************* command log **************/

typedef struct {
    FL_FORM   * form;
    void      * vdata;                  /* UNUSED, remove in later version */
    char      * cdata;                  /* UNUSED, remove in later version */
    long        ldata;                  /* UNUSED, remove in later version */
    FL_OBJECT * browser;
    FL_OBJECT * close_browser;
    FL_OBJECT * clear_browser;
} FD_CMDLOG;

#ifdef FL_WIN32
#define FL_PID_T HANDLE
#else
#define FL_PID_T long
#endif

FL_EXPORT FL_PID_T fl_exe_command( const char *,
                                   int );

FL_EXPORT int fl_end_command( FL_PID_T );

FL_EXPORT int fl_check_command( FL_PID_T );

FL_EXPORT FILE * fl_popen( const char *,
                           const char * );

FL_EXPORT int fl_pclose( FILE * );

FL_EXPORT int fl_end_all_command( void );

FL_EXPORT void fl_show_command_log( int );

FL_EXPORT void fl_hide_command_log( void );

FL_EXPORT void fl_clear_command_log( void );

FL_EXPORT void fl_addto_command_log( const char * );

FL_EXPORT void fl_addto_command_log_f( const char *,
									   ...);

FL_EXPORT void fl_set_command_log_position( int,
                                            int );

FL_EXPORT FD_CMDLOG * fl_get_command_log_fdstruct( void );

/* Aliases */

#define fl_open_command    fl_exe_command
#define fl_close_command   fl_end_command

/******* File selector *****************/

#define FL_MAX_FSELECTOR  6

typedef struct {
    FL_FORM   * fselect;
    void      * vdata;
    void      * cdata;
    long        ldata;
    FL_OBJECT * browser,
              * input,
              * prompt,
              * resbutt;
    FL_OBJECT * patbutt,
              * dirbutt,
              * cancel,
              * ready;
    FL_OBJECT * dirlabel,
              * patlabel;
    FL_OBJECT * appbutt[ 3 ];
} FD_FSELECTOR;

FL_EXPORT int fl_use_fselector( int );

FL_EXPORT const char * fl_show_fselector( const char *,
                                          const char *,
                                          const char *,
                                          const char * );

FL_EXPORT void fl_hide_fselector( void );

FL_EXPORT void fl_set_fselector_fontsize( int );

FL_EXPORT void fl_set_fselector_fontstyle( int );

FL_EXPORT void fl_set_fselector_placement( int );

FL_EXPORT void fl_set_fselector_border( int );

#define fl_set_fselector_transient( b )   \
            fl_set_fselector_border( ( b ) ? FL_TRANSIENT : FL_FULLBORDER )

FL_EXPORT void fl_set_fselector_callback( FL_FSCB,
                                          void * );

FL_EXPORT const char * fl_get_filename( void );

FL_EXPORT const char * fl_get_directory( void );

FL_EXPORT const char * fl_get_pattern( void );

FL_EXPORT int fl_set_directory( const char * );

FL_EXPORT void fl_set_pattern( const char * );

FL_EXPORT void fl_refresh_fselector( void );

FL_EXPORT void fl_add_fselector_appbutton( const char *,
                                           void ( * )( void * ),
                                           void * );

FL_EXPORT void fl_remove_fselector_appbutton( const char * );

FL_EXPORT void fl_disable_fselector_cache( int );

FL_EXPORT void fl_invalidate_fselector_cache( void );

FL_EXPORT FL_FORM * fl_get_fselector_form( void );

FL_EXPORT FD_FSELECTOR * fl_get_fselector_fdstruct( void );

FL_EXPORT void fl_hide_fselector( void );

FL_EXPORT void fl_set_fselector_filetype_marker( int,
                                                 int,
                                                 int,
                                                 int,
                                                 int );

#define fl_show_file_selector     fl_show_fselector
#define fl_set_fselector_cb       fl_set_fselector_callback

#define fl_set_fselector_title( s )   \
        fl_set_form_title( fl_get_fselector_form( ), s )

FL_EXPORT int fl_goodies_atclose( FL_FORM *,
                                  void * );

FL_EXPORT int fl_show_color_chooser( const int * rgb_in,
									 int       * rgb_out );

#endif /* ! defined FL_GOODIES_H */
