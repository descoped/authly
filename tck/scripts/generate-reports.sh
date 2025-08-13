#!/bin/bash
# TCK Report Generation
# Unified report generation for conformance test results

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Configuration
REPORTS_DIR="reports/latest"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "📊 TCK Report Generation"
echo "========================"
echo ""

# Ensure reports directory exists
mkdir -p "$REPORTS_DIR"

# Check if validation has been run
if [[ ! -f "$REPORTS_DIR/SPECIFICATION_CONFORMANCE.md" ]]; then
    echo "⚠️  No conformance report found. Run validation first:"
    echo "   make validate"
    exit 1
fi

echo "📋 Available Reports:"
echo ""

# List all reports with details
if [[ -d "$REPORTS_DIR" ]]; then
    find "$REPORTS_DIR" -type f -name "*.md" -o -name "*.json" | sort | while read -r file; do
        basename_file=$(basename "$file")
        size=$(du -h "$file" | cut -f1)
        modified=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$file" 2>/dev/null || stat -c "%y" "$file" 2>/dev/null | cut -d' ' -f1-2)
        echo "  📄 $basename_file ($size, $modified)"
    done
else
    echo "  ❌ No reports directory found"
    exit 1
fi

echo ""

# Generate report summary
echo "📊 Report Summary:"
echo ""

# Extract key metrics from conformance report
if [[ -f "$REPORTS_DIR/SPECIFICATION_CONFORMANCE.md" ]]; then
    # Extract overall score
    if grep -q "checks passed" "$REPORTS_DIR/SPECIFICATION_CONFORMANCE.md"; then
        SCORE=$(grep "checks passed" "$REPORTS_DIR/SPECIFICATION_CONFORMANCE.md" | head -1 | grep -o '[0-9]*/[0-9]* checks passed ([0-9]*%)')
        echo "  🎯 Overall Compliance: $SCORE"
    fi
    
    # Extract category scores  
    echo "  📋 Category Breakdown:"
    grep "Category Score:" "$REPORTS_DIR/SPECIFICATION_CONFORMANCE.md" | while read -r line; do
        category=$(echo "$line" | grep -o '\*\*.*:\*\*' | tr -d '*:' | head -1)
        score=$(echo "$line" | grep -o '[0-9]*/[0-9]* ([0-9]*%)')
        if [[ -n "$category" ]] && [[ -n "$score" ]]; then
            echo "    • $category: $score"
        fi
    done
fi

echo ""

# Show quick commands
echo "🔧 Quick Commands:"
echo "  cat $REPORTS_DIR/SPECIFICATION_CONFORMANCE.md    # View main report"
echo "  cat $REPORTS_DIR/conformance_results.json        # View JSON results"

if [[ -f "$REPORTS_DIR/COMPREHENSIVE_API_MATRIX.md" ]]; then
    echo "  cat $REPORTS_DIR/COMPREHENSIVE_API_MATRIX.md       # View API matrix"
fi

echo ""

# Optional: Create timestamped backup
if [[ "${1:-}" == "--backup" ]]; then
    BACKUP_DIR="reports/backup_$TIMESTAMP"
    echo "💾 Creating backup: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    cp -r "$REPORTS_DIR"/* "$BACKUP_DIR"/
    echo "✅ Backup created"
    echo ""
fi

# Optional: Generate aggregate report
if [[ "${1:-}" == "--aggregate" ]]; then
    echo "📈 Generating aggregate report..."
    
    AGGREGATE_FILE="$REPORTS_DIR/AGGREGATE_SUMMARY.md"
    
    {
        echo "# TCK Aggregate Report"
        echo ""
        echo "Generated: $(date)"
        echo ""
        echo "## Compliance Summary"
        echo ""
        
        if [[ -f "$REPORTS_DIR/SPECIFICATION_CONFORMANCE.md" ]]; then
            grep "checks passed" "$REPORTS_DIR/SPECIFICATION_CONFORMANCE.md" | head -1
            echo ""
            echo "## Category Details" 
            echo ""
            grep -A 1 "Category Score:" "$REPORTS_DIR/SPECIFICATION_CONFORMANCE.md"
        fi
        
        echo ""
        echo "## Files Generated"
        echo ""
        find "$REPORTS_DIR" -type f | sort | while read -r file; do
            basename_file=$(basename "$file")
            size=$(du -h "$file" | cut -f1)
            echo "- $basename_file ($size)"
        done
        
    } > "$AGGREGATE_FILE"
    
    echo "✅ Aggregate report created: $AGGREGATE_FILE"
    echo ""
fi

echo "✨ Report generation complete!"