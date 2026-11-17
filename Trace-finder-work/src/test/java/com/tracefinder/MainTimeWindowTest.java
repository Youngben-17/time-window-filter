package com.tracefinder;

import com.tracefinder.exception.InvalidArgumentCountException;
import com.tracefinder.exception.InvalidTimeWindowException;
import com.tracefinder.exception.InvalidTimestampException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class MainTimeWindowTest {

    @TempDir
    Path tempDir;

    @Test
    void windowedReportFiltersFindingsButPreservesMalformedLinesAndOriginalLineNumbers() throws Exception {
        Path log = writeLog(
                "not a valid log line\n"
                        + "2024-03-15 01:59:59 | ALERT | 203.0.113.7 | /outside | before\n"
                        + "2024-03-15 02:00:00 | UNKNOWN | 203.0.113.7 | /inside | unknown\n"
                        + "2024-03-15 02:30:00 | ALERT | 203.0.113.7 | /inside | start-range\n"
                        + "2024-03-15 03:30:00 | ALERT | 203.0.113.7 | /edge | end-exclusive\n");
        Path rules = writeRules();
        Path report = tempDir.resolve("window-report.txt");

        Main.run(args(log, rules, report,
                "2024-03-15 02:00:00", "2024-03-15 03:30:00"));

        String text = Files.readString(report);
        assertTrue(text.contains("Time Window: 2024-03-15 02:00:00 to 2024-03-15 03:30:00"));
        assertTrue(text.contains("ALERT: 1"));
        assertTrue(text.contains("203.0.113.7: 2 entries"),
                "IP totals should include every parsed entry in the window, including unknown levels");
        assertTrue(text.contains("Line 3: 2024-03-15 02:00:00 | UNKNOWN"));
        assertTrue(text.contains("Line 1: not a valid log line"));
        assertFalse(text.contains("/outside"));
        assertFalse(text.contains("/edge"));
    }

    @Test
    void equalStartAndEndProducesCompleteEmptyWindowReport() throws Exception {
        Path log = writeLog("2024-03-15 02:00:00 | ALERT | 203.0.113.7 | /x | event\n");
        Path rules = writeRules();
        Path report = tempDir.resolve("empty-report.txt");

        Main.run(args(log, rules, report,
                "2024-03-15 02:00:00", "2024-03-15 02:00:00"));

        String text = Files.readString(report);
        assertTrue(text.contains("Time Window: 2024-03-15 02:00:00 to 2024-03-15 02:00:00"));
        assertTrue(text.contains("ALERT: 0"));
        assertTrue(text.contains("--- Flagged Entries ---\nNone found"));
        assertTrue(text.contains("--- Suspicious Activity by IP ---\nNone found"));
    }

    @Test
    void reversedWindowStopsBeforeWritingReport() throws Exception {
        Path log = writeLog("");
        Path rules = writeRules();
        Path report = tempDir.resolve("report.txt");

        InvalidTimeWindowException error = assertThrows(InvalidTimeWindowException.class,
                () -> Main.run(args(log, rules, report,
                        "2024-03-15 04:00:00", "2024-03-15 03:00:00")));

        assertTrue(error.getMessage().contains("must not be after"));
        assertFalse(Files.exists(report));
    }

    @Test
    void unreadableTimestampStopsWithExpectedFormatMessage() throws Exception {
        Path log = writeLog("");
        Path rules = writeRules();
        Path report = tempDir.resolve("report.txt");

        InvalidTimestampException error = assertThrows(InvalidTimestampException.class,
                () -> Main.run(args(log, rules, report,
                        "2024-02-30 02:00:00", "2024-03-15 03:00:00")));

        assertTrue(error.getMessage().contains("start timestamp"));
        assertTrue(error.getMessage().contains("yyyy-MM-dd HH:mm:ss"));
        assertFalse(Files.exists(report));
    }

    @Test
    void unreadableEndTimestampStopsWithExpectedFormatMessage() throws Exception {
        Path log = writeLog("");
        Path rules = writeRules();
        Path report = tempDir.resolve("report.txt");

        InvalidTimestampException error = assertThrows(InvalidTimestampException.class,
                () -> Main.run(args(log, rules, report,
                        "2024-03-15 02:00:00", "not-a-timestamp")));

        assertTrue(error.getMessage().contains("end timestamp"));
        assertFalse(Files.exists(report));
    }

    @Test
    void ordinaryWindowWithNoEntriesStillWritesCompleteReport() throws Exception {
        Path log = writeLog("2024-03-15 01:00:00 | ALERT | 203.0.113.7 | /x | event\n");
        Path rules = writeRules();
        Path report = tempDir.resolve("no-matches-report.txt");

        Main.run(args(log, rules, report,
                "2024-03-15 02:00:00", "2024-03-15 03:00:00"));

        String text = Files.readString(report);
        assertTrue(text.contains("ALERT: 0"));
        assertTrue(text.contains("--- Flagged Entries ---\nNone found"));
        assertTrue(text.contains("--- Unknown Patterns ---\nNone found"));
        assertTrue(text.contains("--- Malformed Lines ---\nNone found"));
    }

    @Test
    void malformedSectionIsIdenticalInWindowedAndWholeFileReports() throws Exception {
        Path log = writeLog("bad line\n"
                + "2024-03-15 01:00:00 | ALERT | 203.0.113.7 | /before | event\n"
                + "2024-03-15 02:30:00 | ALERT | 203.0.113.7 | /inside | event\n");
        Path rules = writeRules();
        Path wholeReport = tempDir.resolve("whole-report.txt");
        Path windowReport = tempDir.resolve("window-report.txt");

        Main.run(args(log, rules, wholeReport));
        Main.run(args(log, rules, windowReport, "2024-03-15 02:00:00", "2024-03-15 03:00:00"));

        assertEquals(section(Files.readString(wholeReport), "--- Malformed Lines ---"),
                section(Files.readString(windowReport), "--- Malformed Lines ---"));
        assertTrue(Files.readString(windowReport).contains("ALERT: 1"));
        assertTrue(Files.readString(wholeReport).contains("ALERT: 2"));
    }

    @Test
    void anyArgumentCountOtherThanThreeOrFiveIsRejected() {
        InvalidArgumentCountException error = assertThrows(InvalidArgumentCountException.class,
                () -> Main.run(new String[]{"one", "two", "three", "four"}));
        assertTrue(error.getMessage().contains("Expected 3 arguments"));
        assertTrue(error.getMessage().contains("or 5 arguments"));
    }

    @Test
    void threeArgumentsStillAnalyseTheWholeFile() throws Exception {
        Path log = writeLog(
                "2024-03-15 01:59:59 | ALERT | 203.0.113.7 | /before | event\n"
                        + "2024-03-15 03:30:00 | ALERT | 203.0.113.7 | /after | event\n");
        Path rules = writeRules();
        Path report = tempDir.resolve("whole-report.txt");

        Main.run(args(log, rules, report));

        String text = Files.readString(report);
        assertTrue(text.contains("Time Window: full file"));
        assertTrue(text.contains("ALERT: 2"));
        assertTrue(text.contains("203.0.113.7: 2 entries"));
    }

    private String section(String report, String heading) {
        int start = report.indexOf(heading);
        assertTrue(start >= 0, "Missing report section: " + heading);
        int next = report.indexOf("\n--- ", start + heading.length());
        return next < 0 ? report.substring(start) : report.substring(start, next);
    }

    private Path writeLog(String contents) throws Exception {
        Path path = tempDir.resolve("logs.txt");
        Files.writeString(path, contents);
        return path;
    }

    private Path writeRules() throws Exception {
        Path path = tempDir.resolve("rules.csv");
        Files.writeString(path, "level,severity_score\nINFO,1\nALERT,9\n");
        return path;
    }

    private String[] args(Path log, Path rules, Path report, String... window) {
        String[] result = new String[3 + window.length];
        result[0] = log.toString();
        result[1] = rules.toString();
        result[2] = report.toString();
        System.arraycopy(window, 0, result, 3, window.length);
        return result;
    }
}
