/*= -*- c-basic-offset: 4; indent-tabs-mode: nil; -*-
 *
 * librsync -- generate and apply network deltas
 * $Id$
 * 
 * Copyright (C) 2000, 2001 by Martin Pool <mbp@samba.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


/*
 * TODO: A function like perror that includes strerror output.  Apache
 * does this by adding flags as well as the severity level which say
 * whether such information should be included.
 */


/*
 * trace may be turned off.
 *
 * error is always on, but you can return and continue in some way
 *
 * fatal terminates the whole process
 */

/**
 * \brief Log severity levels.
 *
 * These are the same as syslog, at least in glibc.
 *
 * \sa rs_trace_set_level()
 */
typedef enum {
    RS_LOG_EMERG         = 0,   /**< System is unusable */
    RS_LOG_ALERT         = 1,   /**< Action must be taken immediately */
    RS_LOG_CRIT          = 2,   /**< Critical conditions */
    RS_LOG_ERR           = 3,   /**< Error conditions */
    RS_LOG_WARNING       = 4,   /**< Warning conditions */
    RS_LOG_NOTICE        = 5,   /**< Normal but significant condition */
    RS_LOG_INFO          = 6,   /**< Informational */
    RS_LOG_DEBUG         = 7    /**< Debug-level messages */
} rs_loglevel;



/**
 * \typedef rs_trace_fn_t
 * \brief Callback to write out log messages.
 * \param level a syslog level.
 * \param msg message to be logged.
 */
typedef void    rs_trace_fn_t(int level, char const *msg);

void            rs_trace_set_level(rs_loglevel level);

/** Set trace callback. */
void            rs_trace_to(rs_trace_fn_t *);

/** Default trace callback that writes to stderr.  Implements
 * ::rs_trace_fn_t, and may be passed to rs_trace_to(). */
void            rs_trace_stderr(int level, char const *msg);

/** Check whether the library was compiled with debugging trace
 * suport. */
int             rs_supports_trace(void);


void rs_fatal0(char const *s, ...);
void rs_error0(char const *s, ...);
void rs_trace0(char const *s, ...);

#ifdef __GNUC__

void rs_log0(int level, char const *fn, char const *fmt, ...)
    __attribute__ ((format(printf, 3, 4)));

#ifdef DO_RS_TRACE
#  define rs_trace(fmt, arg...)                            \
    do { rs_log0(RS_LOG_DEBUG, __FUNCTION__, fmt , ##arg);  \
    } while (0)
#else
#  define rs_trace(s, str...)
#endif	/* !DO_RS_TRACE */

/*
 * TODO: Don't assume this is a gcc thing; rather test in autoconf for
 * support for __FUNCTION__ and varargs macros.  One simple way might
 * just be to try compiling the definition of one of these functions!
 *
 * TODO: Also look for the C9X predefined identifier `_function', or
 * whatever it's called.
 */

#define rs_log(l, s, str...) do {              \
     rs_log0(l, __FUNCTION__, (s) , ##str);    \
     } while (0)


#define rs_error(s, str...) do {                       \
     rs_log0(RS_LOG_ERR,  __FUNCTION__, (s) , ##str);     \
     } while (0)


#define rs_fatal(s, str...) do {               \
     rs_log0(RS_LOG_CRIT,  __FUNCTION__,          \
	      (s) , ##str);                     \
     abort();                                   \
     } while (0)


#else /************************* ! __GNUC__ */

#  define rs_fatal rs_fatal0
#  define rs_error rs_error0

#  ifdef DO_RS_TRACE
#    define rs_trace rs_trace0
void            rs_log0(int, char const *, ...);
#  endif			/* DO_RS_TRACE */
#endif				/* ! __GNUC__ */


